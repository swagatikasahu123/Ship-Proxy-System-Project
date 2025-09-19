#!/usr/bin/env python3
# client/client.py - Ship-side proxy (listens on 8080)

import socket
import threading
import queue
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# CONFIG (change CONTROL_HOST to offshore server IP when deploying)
CONTROL_HOST = '127.0.0.1'
CONTROL_PORT = 9999
LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = 8080

# framing helpers
def recv_all(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed while reading')
        buf.extend(chunk)
    return bytes(buf)

def read_message(sock):
    hdr = recv_all(sock, 5)
    length = int.from_bytes(hdr[:4], 'big')
    mtype = hdr[4]
    payload = recv_all(sock, length) if length > 0 else b''
    return mtype, payload

def send_message(sock, mtype, payload: bytes):
    header = len(payload).to_bytes(4, 'big') + bytes([mtype])
    sock.sendall(header + payload)

class ControlConnection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.lock = threading.Lock()
        self.receiver_thread = None
        self.running = False
        self.response_event = threading.Event()
        self.last_response = None
        # for tunnel
        self.tunnel_target_sock = None
        self._tunnel_buffer = queue.Queue()

    def connect(self):
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.host, self.port))
                self.sock = s
                self.running = True
                self.receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
                self.receiver_thread.start()
                print('[client] connected to control', self.host, self.port)
                break
            except Exception as e:
                print('[client] cannot connect to control; retrying in 2s', e)
                time.sleep(2)

    def _receiver_loop(self):
        try:
            while self.running:
                mtype, payload = read_message(self.sock)
                if mtype == 1:  # RESPONSE
                    self.last_response = payload
                    self.response_event.set()
                elif mtype == 2:  # TUNNEL_DATA
                    if self.tunnel_target_sock:
                        try:
                            self.tunnel_target_sock.sendall(payload)
                        except Exception:
                            pass
                    else:
                        # buffer until a handler attaches to the tunnel
                        self._tunnel_buffer.put(payload)
                elif mtype == 3:  # TUNNEL_CLOSE
                    if self.tunnel_target_sock:
                        try:
                            self.tunnel_target_sock.shutdown(socket.SHUT_RDWR)
                            self.tunnel_target_sock.close()
                        except:
                            pass
                        self.tunnel_target_sock = None
                else:
                    print('[client] unknown message type', mtype)
        except ConnectionError:
            print('[client] control connection closed')
            self.running = False
        except Exception as e:
            print('[client] receiver exception', e)
            self.running = False

    def send_request_and_wait(self, raw_request_bytes, timeout=60):
        with self.lock:
            self.response_event.clear()
            send_message(self.sock, 0, raw_request_bytes)
            got = self.response_event.wait(timeout=timeout)
            if not got:
                return None
            data = self.last_response
            self.last_response = None
            return data

control = ControlConnection(CONTROL_HOST, CONTROL_PORT)

# Request processor with sequential worker
class RequestProcessor:
    def __init__(self, control):
        self.control = control
        self.q = queue.Queue()
        self.worker = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker.start()

    def enqueue_and_wait(self, raw_request_bytes, handler, is_tunnel=False):
        item = {'req': raw_request_bytes, 'handler': handler, 'is_tunnel': is_tunnel, 'evt': threading.Event(), 'resp': None}
        self.q.put(item)
        item['evt'].wait(timeout=90)
        return item['resp']

    def _worker_loop(self):
        while True:
            item = self.q.get()
            raw = item['req']
            try:
                resp = self.control.send_request_and_wait(raw)
                item['resp'] = resp
                item['evt'].set()
            except Exception:
                item['resp'] = None
                item['evt'].set()

request_processor = None  # set after control.connect()

# Proxy HTTP handler
class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_METHOD(self):
        # read body if present
        content_length = self.headers.get('Content-Length')
        body = b''
        if content_length:
            try:
                n = int(content_length); body = self.rfile.read(n)
            except:
                body = self.rfile.read()
        # build raw proxy-style request (absolute-form for proxies typically)
        req_line = f'{self.command} {self.path} {self.request_version}\r\n'
        headers = ''
        # ensure Host header exists
        if 'host' not in {k.lower() for k in self.headers}:
            headers += f'Host: {self.server.server_name}\r\n'
        for k, v in self.headers.items():
            headers += f'{k}: {v}\r\n'
        raw = (req_line + headers + '\r\n').encode('iso-8859-1') + (body or b'')

        response_bytes = request_processor.enqueue_and_wait(raw, self)
        if not response_bytes:
            self.send_error(504, 'Gateway Timeout')
            return

        # parse response bytes and send back
        sep = b'\r\n\r\n'
        idx = response_bytes.find(sep)
        sep_len = 4
        if idx == -1:
            idx = response_bytes.find(b'\n\n')
            sep_len = 2
        if idx == -1:
            # malformed - send raw bytes
            try:
                self.wfile.write(response_bytes)
            except:
                pass
            return
        head = response_bytes[:idx].decode('iso-8859-1')
        body = response_bytes[idx+sep_len:]
        lines = head.splitlines()
        status_line = lines[0]
        try:
            proto, status_code, reason = status_line.split(' ', 2)
            status_code = int(status_code)
            self.send_response(status_code, reason)
        except:
            self.send_response(200)
        for line in lines[1:]:
            if not line.strip():
                continue
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            self.send_header(k.strip(), v.strip())
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except:
                pass

    do_GET = do_METHOD; do_POST = do_METHOD; do_PUT = do_METHOD; do_DELETE = do_METHOD
    do_PATCH = do_METHOD; do_OPTIONS = do_METHOD; do_HEAD = do_METHOD

    def do_CONNECT(self):
        # build CONNECT raw request
        hostport = self.path
        req_line = f'CONNECT {hostport} {self.request_version}\r\n'
        headers = ''
        for k, v in self.headers.items():
            headers += f'{k}: {v}\r\n'
        raw = (req_line + headers + '\r\n').encode('iso-8859-1')

        resp = request_processor.enqueue_and_wait(raw, self, is_tunnel=True)
        if not resp:
            self.send_error(502, 'Bad Gateway'); return

        # parse status
        sep = b'\r\n\r\n'
        idx = resp.find(sep)
        head = resp[:idx].decode('iso-8859-1') if idx != -1 else resp.decode('iso-8859-1')
        first_line = head.splitlines()[0] if head else ''
        if '200' not in first_line:
            # forward response to client
            try:
                self.wfile.write(resp)
            except:
                pass
            return

        # send 200 to client
        try:
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        except:
            return

        client_sock = self.connection
        # attach tunnel socket and flush any buffered data from control
        control.tunnel_target_sock = client_sock
        while not control._tunnel_buffer.empty():
            try:
                data = control._tunnel_buffer.get_nowait()
                if data:
                    client_sock.sendall(data)
            except queue.Empty:
                break
            except Exception:
                pass

        # read from client and forward as TUNNEL_DATA frames to control
        try:
            while True:
                data = client_sock.recv(4096)
                if not data:
                    # tell server to close tunnel
                    try:
                        send_message(control.sock, 3, b'')
                    except:
                        pass
                    break
                send_message(control.sock, 2, data)
        except Exception:
            try:
                send_message(control.sock, 3, b'')
            except:
                pass
        finally:
            control.tunnel_target_sock = None

def run_proxy():
    global control, request_processor
    control.connect()
    request_processor = RequestProcessor(control)
    server = HTTPServer((LISTEN_ADDR, LISTEN_PORT), ProxyHandler)
    print(f'[client] http proxy listening on {LISTEN_ADDR}:{LISTEN_PORT}')
    server.serve_forever()

if __name__ == '__main__':
    control = ControlConnection(CONTROL_HOST, CONTROL_PORT)
    run_proxy()

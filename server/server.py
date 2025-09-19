#!/usr/bin/env python3
# server/server.py - Offshore proxy server (listens on 9999)

import socket
import threading
import traceback
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse

HOST = '0.0.0.0'
PORT = 9999

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

def build_raw_response(status_code, reason, headers, body_bytes):
    status_line = f'HTTP/1.1 {status_code} {reason}\r\n'
    hdr_lines = ''.join(f'{k}: {v}\r\n' for k, v in headers.items())
    return (status_line + hdr_lines + '\r\n').encode('iso-8859-1') + (body_bytes or b'')

def parse_raw_http_request(data: bytes):
    sep = b'\r\n\r\n'
    idx = data.find(sep)
    sep_len = 4
    if idx == -1:
        idx = data.find(b'\n\n')
        sep_len = 2
        if idx == -1:
            raise ValueError('invalid http request (no header/body separator)')
    head = data[:idx].decode('iso-8859-1')
    body = data[idx+sep_len:]
    lines = head.splitlines()
    method, path, version = lines[0].split(' ', 2)
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        headers[k.strip().lower()] = v.strip()
    return method, path, version, headers, body

class ControlHandler:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.lock = threading.Lock()
        self.running = True

    def handle(self):
        try:
            while self.running:
                mtype, payload = read_message(self.conn)
                if mtype == 0:  # REQUEST
                    try:
                        method, path, version, headers, body = parse_raw_http_request(payload)
                    except Exception:
                        resp = build_raw_response(400, 'Bad Request', {'connection': 'close'}, b'Bad Request')
                        with self.lock:
                            send_message(self.conn, 1, resp)
                        continue

                    if method.upper() == 'CONNECT':
                        # CONNECT -> establish tunnel
                        hostport = path
                        host, sep, port_s = hostport.partition(':')
                        port = int(port_s) if sep else 443
                        try:
                            target = socket.create_connection((host, port), timeout=10)
                        except Exception:
                            resp = build_raw_response(502, 'Bad Gateway', {'connection': 'close'}, b'Cannot connect to target')
                            with self.lock:
                                send_message(self.conn, 1, resp)
                            continue

                        # respond 200 to the ship proxy (so browser thinks CONNECT succeeded)
                        resp = build_raw_response(200, 'Connection Established', {'connection': 'keep-alive'}, b'')
                        with self.lock:
                            send_message(self.conn, 1, resp)

                        # thread: read from target -> send TUNNEL_DATA(2) frames to ship
                        def target_to_control(tgt_sock):
                            try:
                                while True:
                                    data = tgt_sock.recv(4096)
                                    if not data:
                                        with self.lock:
                                            send_message(self.conn, 3, b'')  # tunnel close
                                        break
                                    with self.lock:
                                        send_message(self.conn, 2, data)
                            except Exception:
                                with self.lock:
                                    try:
                                        send_message(self.conn, 3, b'')
                                    except:
                                        pass
                            finally:
                                try: tgt_sock.close()
                                except: pass

                        t_thread = threading.Thread(target=target_to_control, args=(target,), daemon=True)
                        t_thread.start()

                        # main loop now receives TUNNEL_DATA frames from ship and forwards to target
                        try:
                            while True:
                                m2, payload2 = read_message(self.conn)
                                if m2 == 2:
                                    if payload2:
                                        target.sendall(payload2)
                                elif m2 == 3:
                                    break
                                else:
                                    # ignore other frame types while tunnel is active
                                    pass
                        except ConnectionError:
                            pass
                        finally:
                            try: target.close()
                            except: pass
                            # let target_to_control thread end
                            t_thread.join(timeout=1)
                        continue  # go back to normal main loop
                    else:
                        # Regular HTTP forwarding
                        host_hdr = headers.get('host')
                        if not host_hdr:
                            resp = build_raw_response(400, 'Bad Request', {'connection':'close'}, b'Host header missing')
                            with self.lock:
                                send_message(self.conn, 1, resp)
                            continue

                        url = urlparse(path)
                        if url.scheme:
                            conn_host = url.hostname
                            conn_port = url.port or (443 if url.scheme == 'https' else 80)
                            req_path = url.path or '/'
                            if url.query:
                                req_path += '?' + url.query
                            scheme = url.scheme
                        else:
                            if ':' in host_hdr:
                                conn_host, port_s = host_hdr.split(':', 1); conn_port = int(port_s)
                            else:
                                conn_host = host_hdr; conn_port = 80
                            req_path = path; scheme = 'http'

                        try:
                            if scheme == 'https':
                                c = HTTPSConnection(conn_host, conn_port, timeout=30)
                            else:
                                c = HTTPConnection(conn_host, conn_port, timeout=30)
                            forward_headers = {k: v for k, v in headers.items() if k.lower() not in ('proxy-connection', 'connection', 'keep-alive')}
                            c.request(method, req_path, body=body if body else None, headers=forward_headers)
                            r = c.getresponse()
                            resp_body = r.read()
                            resp_headers = {k: v for k, v in r.getheaders()}
                            raw_resp = build_raw_response(r.status, r.reason, resp_headers, resp_body)
                            with self.lock:
                                send_message(self.conn, 1, raw_resp)
                            c.close()
                        except Exception:
                            tb = traceback.format_exc()
                            print('[server] forward error:', tb)
                            resp = build_raw_response(502, 'Bad Gateway', {'connection':'close'}, b'Bad Gateway')
                            with self.lock:
                                send_message(self.conn, 1, resp)
                else:
                    # Unknown or unexpected frames at top-level are ignored
                    print('[server] unexpected frame type at top level:', mtype)
        except ConnectionError:
            print('[server] control connection closed')
        except Exception:
            traceback.print_exc()
        finally:
            try: self.conn.close()
            except: pass

def main():
    print(f'[server] listening on {HOST}:{PORT}')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        print('[server] control connection from', addr)
        handler = ControlHandler(conn, addr)
        t = threading.Thread(target=handler.handle, daemon=True)
        t.start()

if __name__ == '__main__':
    main()

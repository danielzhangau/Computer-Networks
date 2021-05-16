import sys
import socketserver
import os
import threading
import traceback

MAX_SIZE = 4096
HOST = "127.0.0.1"
PORT = 0

sock_dict = {}


class ThreadedTCPHandshakesHandler(socketserver.StreamRequestHandler):
    global sock_dict

    def handle(self):
        while True:
            sock_dict[self.client_address[1]] = self.request
            message = str(self.request.recv(MAX_SIZE), 'ascii')
            forward = f"[PID]{os.getpid()}[P]{self.client_address[1]}[R]{message}\n"
            sys.stdout.write(forward)
            sys.stdout.flush()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def send_packet(message, target):
    global sock_dict
    try:
        port = int(target)
        sock = sock_dict.get(port)
        raw_message = message.encode("utf-8")
        sock.sendall(raw_message)
    except:
        traceback.print_exc()
        print("COULD NOT SEND THE PACKET", flush=True)


def main():
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPHandshakesHandler)
    with server:
        addr, port = server.server_address
        print(f"{port}", flush=True)
        t = threading.Thread(target=server.serve_forever)
        t.start()
        while True:
            ins = input()
            print("Server received a command from the Handle.", flush=True)
            if "SEND" in ins:
                lst = ins.split()
                send_packet(lst[2], lst[1])
            else:
                break
        server.shutdown()


if __name__ == "__main__":
    main()

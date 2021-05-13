import sys
import socketserver
import os
import time
from multiprocessing import Process

MAX_SIZE = 4096
HOST = "127.0.0.1"
PORT = 0


class ForkTCPHandshakesHandler(socketserver.StreamRequestHandler):

    def handle(self) -> None:
        while True:
            message = str(self.request.recv(MAX_SIZE), 'ascii')
            forward = f"[PID]{os.getpid()}[P]{self.client_address[1]}[R]{message}\n"
            sys.stdout.write(forward)
            sys.stdout.flush()


class ForkTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def main():
    server = ForkTCPServer((HOST, PORT), ForkTCPHandshakesHandler)
    with server:
        addr, port = server.server_address
        print(f"{port}", flush=True)
        p = Process(target=server.serve_forever)
        p.start()
        time.sleep(60)
        server.shutdown()


if __name__ == "__main__":
    main()

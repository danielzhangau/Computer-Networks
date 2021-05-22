import socket
import sys
import threading
import struct
import time
import traceback

RUSHB_TESTADAPTER_VERSION = "1.1"
LOCALHOST = "127.0.0.1"

PACKET_SIZE = 4096
RECV_SIZE = 4096

DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA = 0x05
QUERY = 0x06
AVAILABLE = 0x07
LOCATION = 0x08
DISTANCE = 0x09
MORE_FRAG = 0x0a
END_FRAG = 0x0b
INVALID = 0x00


# class GreetingProtocol(Packet):
#     name = "RUSH"
#     fields_desc = [
#         BitField("source_ip", 0, 32),
#         BitField("destination_ip", 0, 32),
#         BitField("offset", 0, 24),
#         BitField("mode", 0, 8),
#     ]
#
#
# class RUSHIp(GreetingProtocol):
#     name = "RUSH_IP"
#     fields_desc = [
#         BitField("ip", 0, 32),
#     ]


def str_to_int(string):
    b_str = string.encode("UTF-8")
    return int.from_bytes(b_str, byteorder='big')


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def build_packet(source_ip, destination_ip, mode, misc=None):
    s_ip = ip_to_int(source_ip)
    d_ip = ip_to_int(destination_ip)
    try:
        # pkt = GreetingProtocol(source_ip=s_ip, destination_ip=d_ip, offset=offset, mode=mode)
        pkt = ''
        pkt += bin(s_ip)[2:].zfill(32)
        pkt += bin(d_ip)[2:].zfill(32)
        pkt += bin(mode)[2:].zfill(32)
        pkt = bytes([int(pkt[i:i + 8], 2) for i in range(0, 96, 8)])
        if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            t_ip = ip_to_int(misc)
            additional = ''
            additional += bin(t_ip)[2:].zfill(32)
            additional = bytes([int(additional[i:i + 8], 2) for i in range(0, 32, 8)])
        elif mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
            additional = misc.encode('utf-8')
        elif mode == LOCATION:
            additional = ''
            additional += bin(misc[0])[2:].zfill(16)
            additional += bin(misc[1])[2:].zfill(16)
            additional = bytes([int(additional[i:i + 8], 2) for i in range(0, 32, 8)])
        else:
            additional = None
    except:
        traceback.print_exc(file=sys.stderr)
        assert False, f"There is a problem while building packet."
    return pkt, additional


class Connection:
    def __init__(self, my_ip, serv_ip, serv_port, output=sys.stdout):
        self._my_ip = my_ip
        self._my_port = None
        self._serv_info = (serv_ip, serv_port)
        self._socket = None
        self._output = output
        self._start_time = time.time()
        self.source_ip = None
        self.destination_ip = None
        self.left_over = ''

    def connect(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((self._my_ip, 0))
            ip, port = self._socket.getsockname()
            self._my_port = port
            return True
        except socket.error as err:
            print("Error encountered when opening socket:\n", err)
            return False

    def _print(self, pkt, additional, init=""):
        if pkt.mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            misc = f"assigned_ip={int_to_ip(additional.ip)}"
        else:
            misc = "no_extra_data"
        output = f"{init}(source_ip={int_to_ip(pkt.source_ip)}, destination_ip={int_to_ip(pkt.destination_ip)}, " \
                 f"offset={0}, mode={pkt.mode}, {misc})"
        sys.stderr.write(output + "\n")
        sys.stderr.flush()

    def _send(self, pkt, additional, sock, target_info=None, print_out=False):
        try:
            message = pkt
            if additional is not None:
                message += additional
            if target_info is None:
                # sock.sendall(message)
                sock.sendto(message, self._serv_info)
            else:
                sock.sendto(message, target_info)
            if print_out:
                self._print(pkt, additional, f"Sent: ")
        except:
            traceback.print_exc(file=sys.stderr)
            assert False, f"Error while sending a message to a socket."

    def recv_pkt(self):
        # sys.stderr.write("receiving packages... \n")
        while True:
            message, address = self._socket.recvfrom(RECV_SIZE)

            self._serv_info = address

            source_ip = int_to_ip(int.from_bytes(message[:4], byteorder='big'))
            self.source_ip = source_ip
            destination_ip = int_to_ip(int.from_bytes(message[4:8], byteorder='big'))
            self.destination_ip = destination_ip
            offset = int.from_bytes(message[8:11], byteorder='big')
            mode = message[11]
            if mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
                left_over = message[12:].decode('utf-8')
            else:
                left_over = int_to_ip(int.from_bytes(message[12:], byteorder='big'))
            sys.stderr.write("source_ip={}, destination_ip={}, offset={}, mode={}, assigned_ip={} \n"
                             .format(source_ip, destination_ip, offset, mode, left_over))

            if mode == OFFER:
                sys.stderr.write("i received offer!, will send request\n")
                pkt, add = build_packet(source_ip="0.0.0.0", destination_ip=source_ip, mode=REQUEST, misc=left_over)
                self._send(pkt, add, self._socket, print_out=False)
                break

            if mode == ACKNOWLEDGE:
                sys.stderr.write("i received acknowledge!\n")
                break

            if mode == QUERY:
                sys.stderr.write("i received query!, will send available\n")
                pkt, add = build_packet(source_ip=destination_ip, destination_ip=source_ip, mode=AVAILABLE)
                self._send(pkt, add, self._socket, print_out=False)

            if mode == DATA:
                sys.stderr.write("i received message: {}\n".format(left_over))
                self._output.write("\b\bReceived from {}: {}\n".format(source_ip, left_over))
                self._output.write("> \n")
                self._output.flush()

            if mode == MORE_FRAG:
                self.left_over += left_over

            if mode == END_FRAG:
                self.left_over += left_over
                self._output.write("\b\bReceived from {}: {}\n".format(source_ip, self.left_over))
                self._output.write("> \n")
                self._output.flush()

    def adapter_greeting(self):
        sock = self._socket
        port = str(sock.getsockname()[1])
        sys.stderr.write(port + "\n")
        sys.stderr.flush()
        # SEND DISCOVERY
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, sock, print_out=False)
        # RECEIVE OFFER THEN SEND REQUEST
        self.recv_pkt()
        # RECEIVE ACKNOWLEDGE
        self.recv_pkt()

        return sock

    def close(self):
        self._socket.close()


def main(argv):
    sys.stderr.write("RUSHB_APAPTER_VERSION: " + RUSHB_TESTADAPTER_VERSION + "\n")
    if len(argv) <= 1 or not argv[1].isdigit():
        print("Usage: python3 RUSHBAdapter.py server_port")
        return

    serv_port = int(argv[1])

    output = sys.stdout

    conn = Connection(LOCALHOST, LOCALHOST, serv_port, output)
    if not conn.connect():
        return

    conn.adapter_greeting()

    # QUERY DATA FREG in threading
    t = threading.Thread(target=conn.recv_pkt)
    t.start()

    while True:
        sys.stdout.write("> ")
        sys.stdout.flush()
        try:
            line = input("")
        except EOFError:
            break
        # line = sys.stdin.readline()
        first_word = line.split()[0]
        if first_word == "send":
            address = line.split()[1]
            message = line.split()[2].strip('"')
            sys.stderr.write(message + "\n")
            pkt, add = build_packet(source_ip=conn.destination_ip, destination_ip=address, mode=DATA, misc=message)
            conn._send(pkt, add, conn._socket, print_out=False)
            sys.stderr.write("i sent data!\n")
        else:
            sys.stderr.write("error: send message in following format: > send {receiver_ip_address} {message}\n")

    sys.stderr.write(':::: finished\n')
    conn.close()
    if output != sys.stdout:
        output.close()


if __name__ == "__main__":
    main(sys.argv)

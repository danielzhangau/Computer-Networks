# cd ass2/RUSHBNetwork
# Import the socket and datetime module
import math
import socket
import struct
import sys
import threading
import time
import traceback

LOCALIP = "127.0.0.1"

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
        elif mode == DISTANCE:
            t_ip = ip_to_int(misc[0])
            additional = ''
            additional += bin(t_ip)[2:].zfill(32)
            additional += bin(int(misc[1]))[2:].zfill(32)
            additional = bytes([int(additional[i:i + 8], 2) for i in range(0, 64, 8)])
        else:
            additional = None
    except:
        traceback.print_exc(file=sys.stderr)
        assert False, f"There is a problem while building packet."
    return pkt, additional


def accept_client(switch_server, add_ip_address=None):
    # act as a server, just receive pkt at the moment
    while True:
        if switch_server.add_tcp_socket is not None:
            client_sock, address = switch_server.add_tcp_socket.accept()
        else:
            client_sock, address = switch_server.socket.accept()
        sys.stderr.write('Accepted connection from {}:{}\n'.format(address[0], address[1]))
        sys.stderr.write('socket {} can start send greeting!\n'.format(client_sock))
        # wait for greeting
        client_handler = threading.Thread(target=switch_server.recv_pkt, args=(client_sock, address,))
        client_handler.start()

        if add_ip_address is not None:
            switch_server.source_ip = add_ip_address
            switch_server.number_of_client = 1


def new_socket(givenPort, switch_server, mode):
    # act as a client
    newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sys.stderr.write("new socket created to connect switch server: {}\n".format(newSocket))
    newSocket.connect((LOCALIP, int(givenPort)))
    switch_server.switch_greeting(givenPort, mode, newSocket)


class SwitchServer:
    """ A simple Switch Server """

    def __init__(self, host, source_ip, x=None, y=None):
        self._host = host  # Host address
        self.argc = 0
        self.socket = None  # Socket
        self.minimap_socks = []  # special for minimap
        self.minimap_data = None
        self.minimap_last_step = False
        self.data_from_src = None
        self.data_from_des = None
        self.add_tcp_socket = None
        self._client_info = None
        self._server_info = None
        self.source_ip = source_ip
        self.assigned_ip = None
        self.number_of_client = 1
        self.mode = None
        self._x = x
        self._y = y
        self.distance_dict = {}
        self._sent_location = False
        self.neighbor_sock_address = []

    def configure_server(self, mode, argv_len):
        self.mode = mode
        self.argc = argv_len
        if mode == "global":
            # create TCP socket with IPv4 addressing
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            # create UDP socket with IPv4 addressing
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # bind server to the address
        self.socket.bind((self._host, 0))
        ip, port = self.socket.getsockname()
        port = str(port)
        sys.stdout.write(port + "\n")
        sys.stdout.flush()
        if mode == "global":
            self.socket.listen()  # max backlog of connections

        # local2 condition: one udp, one tcp
        if mode == "local" and argv_len > 5:
            # create TCP socket with IPv4 addressing
            self.add_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.add_tcp_socket.bind((self._host, 0))
            tcp_ip, tcp_port = self.add_tcp_socket.getsockname()
            tcp_port = str(tcp_port)
            sys.stdout.write(tcp_port + "\n")
            sys.stdout.flush()
            self.add_tcp_socket.listen()  # max backlog of connections

    def _send(self, pkt, additional, sock, target_info=None):
        time.sleep(0.2)
        try:
            message = bytes(pkt)
            if additional is not None:
                message += bytes(additional)
            if target_info is None:
                if self.mode == 'global':
                    sys.stderr.write("_server_info: {}\n".format(self._server_info))
                    sock.sendto(message, self._server_info)
                    sys.stderr.write("I send message:{} to info:{}\n".format(message, self._server_info))
                else:
                    sock.sendto(message, self._client_info)
                    sys.stderr.write("I send message:{} to info:{}\n".format(message, self._client_info))
            else:
                sock.sendto(message, target_info)
                sys.stderr.write("I send message:{} to info:{}\n".format(message, target_info))

        except:
            traceback.print_exc(file=sys.stderr)
            assert False, f"Error while sending a message to a socket."

    def recv_pkt(self, newSock=None, newAddress=None, switchDisSwitchMode=None):
        """action when the server receives a client’s file request """
        sys.stderr.write("receiving packages... \n")
        if newSock is None:
            newSock = self.socket

        while True:
            message, address = newSock.recvfrom(RECV_SIZE)
            self._client_info = address

            # deal with packet information
            source_ip = int_to_ip(int.from_bytes(message[:4], byteorder='big'))
            destination_ip = int_to_ip(int.from_bytes(message[4:8], byteorder='big'))
            offset = int.from_bytes(message[8:11], byteorder='big')
            mode = message[11]
            if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
                left_over = int_to_ip(int.from_bytes(message[12:], byteorder='big'))
            elif mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
                left_over = message[12:].decode('utf-8')
            elif mode == LOCATION:
                x = int.from_bytes(message[12:14], byteorder='big')
                y = int.from_bytes(message[14:], byteorder='big')
            elif mode == DISTANCE:
                target_ip = int_to_ip(int.from_bytes(message[12:16], byteorder='big'))
                distance = int.from_bytes(message[16:], byteorder='big')
            else:
                left_over = ""
            sys.stderr.write("source_ip={}, destination_ip={}, offset={}, mode={}, assigned_ip={} \n"
                             .format(source_ip, destination_ip, offset, mode, left_over))

            # if 'discovery' receive, then send 'offer' to client
            if mode == DISCOVERY:
                sys.stderr.write("i received discovery!, will send offer\n")
                # assigned_id need to be incremented
                assigned_ip = ip_to_int(self.source_ip) + self.number_of_client
                self.assigned_ip = int_to_ip(assigned_ip)
                self.number_of_client += 1
                pkt, add = build_packet(source_ip=self.source_ip, destination_ip="0.0.0.0", mode=OFFER,
                                        misc=self.assigned_ip)
                self._send(pkt, add, newSock, target_info=newAddress)

            if mode == OFFER:
                sys.stderr.write("i received offer!, will send request\n")
                pkt, add = build_packet(source_ip="0.0.0.0", destination_ip=source_ip, mode=REQUEST, misc=left_over)
                self._send(pkt, add, newSock, target_info=newAddress)

            # if 'request' receive, then send 'acknowledge'
            if mode == REQUEST:
                sys.stderr.write("i received request!, will send acknowledge\n")
                pkt, add = build_packet(source_ip=self.source_ip, destination_ip=self.assigned_ip, mode=ACKNOWLEDGE,
                                        misc=left_over)
                self._send(pkt, add, newSock, target_info=newAddress)

            if mode == ACKNOWLEDGE:
                sys.stderr.write("i received acknowledge, finished greeting, will send location!\n")
                pkt, add = build_packet(source_ip=destination_ip, destination_ip=source_ip, mode=LOCATION,
                                        misc=(self._x, self._y))
                self._send(pkt, add, newSock, target_info=newAddress)
                self._sent_location = True

            if mode == QUERY:
                sys.stderr.write("i received query!, will send available\n")
                pkt, add = build_packet(source_ip=destination_ip, destination_ip=source_ip, mode=AVAILABLE)
                self._send(pkt, add, newSock, target_info=newAddress)

            # if 'data' receive, just output in stdout
            if mode == DATA:
                sys.stderr.write("i received message: {}\n".format(left_over))
                sys.stdout.write("\b\bReceived from {}: {}\n".format(source_ip, left_over))
                sys.stdout.flush()
                if self.minimap_last_step:
                    sys.stderr.write(source_ip)
                    sys.stderr.write(destination_ip)
                else:
                    self.minimap_data = left_over
                    # in minimap, T receive data from S1, wanna send to S2
                    self.distance_dict.pop([*self.distance_dict.keys()][-1])
                    item = [*self.distance_dict.keys()][-1]
                    del self.distance_dict[item]
                    src_item = ip_to_int(item) + 1
                    src_item = int_to_ip(src_item)
                    self.data_from_src = source_ip
                    self.data_from_des = destination_ip
                    pkt, add = build_packet(source_ip=src_item, destination_ip=item, mode=QUERY)
                    print(len(self.minimap_socks), flush=True)
                    for items in self.minimap_socks:
                        if items != newSock:
                            print(items, flush=True)
                            self._send(pkt, add, items, target_info=None)

            if mode == AVAILABLE:
                sys.stderr.write("i received available, will send data!")
                if self.minimap_last_step:
                    pkt, add = build_packet(source_ip=self.data_from_des, destination_ip=self.data_from_src, mode=DATA,
                                            misc=self.minimap_data)
                    self._send(pkt, add, self.neighbor_sock_address[0][0], self.neighbor_sock_address[0][1])
                else:
                    pkt, add = build_packet(source_ip=self.data_from_src, destination_ip=self.data_from_des, mode=DATA, misc=self.minimap_data)
                    self._send(pkt, add, newSock, target_info=newAddress)
                    self.minimap_last_step = True

                    item = [*self.distance_dict.keys()][0]
                    del self.distance_dict[item]
                    src_item = ip_to_int(item) - 1
                    src_item = int_to_ip(src_item)
                    pkt, add = build_packet(source_ip=src_item, destination_ip=item, mode=QUERY)
                    self._send(pkt, add, self.neighbor_sock_address[0][0], self.neighbor_sock_address[0][1])


            # receive location, send back my location
            if mode == LOCATION:
                sys.stderr.write("i received location!, will send back my location\n")
                # update distance dictionary
                self.distance_dict[source_ip] = math.sqrt((x - self._x) ** 2 + (y - self._y) ** 2)

                self.minimap_socks.append(newSock)
                if self._sent_location is False:
                    pkt, add = build_packet(source_ip=self.source_ip, destination_ip=self.assigned_ip, mode=LOCATION,
                                            misc=(self._x, self._y))
                    self._send(pkt, add, newSock, target_info=newAddress)

                if self.add_tcp_socket is not None:
                    self.distance_dict['10.0.0.1'] = 0
                    self.broadcast(self.assigned_ip, self.distance_dict[source_ip], newAddress, newSock)
                # special for the local2
                elif switchDisSwitchMode == "local":
                    self.source_ip = '135.0.0.2'
                    self.assigned_ip = '135.0.0.1'
                    self.broadcast(self.assigned_ip, self.distance_dict[source_ip], newAddress, newSock)
                else:
                    self.broadcast(self.assigned_ip, self.distance_dict[source_ip], newAddress, newSock)
                # return

            if mode == DISTANCE:
                sys.stderr.write("i received distance!\n")
                if self.add_tcp_socket is None or switchDisSwitchMode != "local":
                    self.distance_dict[target_ip] = distance
                    pkt, add = build_packet(source_ip=self.source_ip, destination_ip=self.assigned_ip, mode=DISTANCE,
                                            misc=(
                                            target_ip, self.distance_dict[target_ip] + self.distance_dict[source_ip]))
                    self._send(pkt, add, self.neighbor_sock_address[0][0], self.neighbor_sock_address[0][1])

    def switch_greeting(self, port_number, mode, newSocket=None, ):
        if newSocket is None:
            return
        self._server_info = (LOCALIP, int(port_number))
        # SEND DISCOVERY
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, newSocket, self._server_info)
        if mode == "local":
            self.recv_pkt(newSock=newSocket, newAddress=self._server_info, switchDisSwitchMode=mode)
        else:
            self.recv_pkt(newSock=newSocket)

    def broadcast(self, now_connected_ip, now_connected_distance, newAddress, newSock):
        print(self.distance_dict, flush=True)
        if newAddress is not None:
            self.neighbor_sock_address.append((newSock, newAddress))
        print(self.neighbor_sock_address, flush=True)
        # broadcast distance to neighbors
        for ip, dis in self.distance_dict.items():
            if ip != now_connected_ip:
                pkt, add = build_packet(source_ip=self.source_ip, destination_ip=now_connected_ip,
                                        mode=DISTANCE, misc=(ip, dis + now_connected_distance))
                sys.stderr.write("source_ip={}, destination_ip={}, mode={}, misc=({}, {}) \n"
                                 .format(self.source_ip, now_connected_ip, DISTANCE, ip, dis + now_connected_distance))
                self._send(pkt, add, self.neighbor_sock_address[0][0], self.neighbor_sock_address[0][1])

    def close(self):
        self.socket.close()


def main(argv):
    if len(argv) < 5 or (argv[1] != 'local' and argv[1] != 'global'):
        print("Usage: python RUSHBSwitch.py {local|global} {ip} [optional_ip] {x} {y}")
        return

    mode = argv[1]
    # ip example: 129.168.0.1/24
    ip = argv[2]
    ip = ip.split("/")
    ip_address = ip[0]
    sys.stderr.write(ip_address + "\n")
    ip_num = ip[1]
    add_ip_address = None
    if len(argv) > 5:
        add_ip = argv[3]
        add_ip = add_ip.split("/")
        add_ip_address = add_ip[0]
        sys.stderr.write(add_ip_address + "\n")
        x = int(argv[4])
        y = int(argv[5])
    else:
        x = int(argv[3])
        y = int(argv[4])

    # Create a Switch Server  and respond to a client's request
    switch_server = SwitchServer(LOCALIP, ip_address, x, y)
    switch_server.configure_server(mode, len(argv))

    # receive packet in threading, so server can receive and send AT THE SAME TIME
    if mode == "local" and len(argv) > 5:
        t = threading.Thread(target=accept_client, args=(switch_server, add_ip_address,))
        t.start()
        t2 = threading.Thread(target=switch_server.recv_pkt)
        t2.start()
    elif mode == "global":
        t = threading.Thread(target=accept_client, args=(switch_server,))
        t.start()
    else:
        t = threading.Thread(target=switch_server.recv_pkt)
        t.start()

    # taking user command, now it's only used in GLOBAL mode
    while True:
        sys.stdout.write("> ")
        sys.stdout.flush()
        try:
            line = input("")
        except EOFError:
            break
        if mode == "global" or (mode == "local" and add_ip_address is None):
            try:
                first_word = line.split()[0]
            except IndexError:
                continue
            if first_word == "connect":
                port = line.split()[1]
                # switch_server.socket.connect((LOCALIP, int(port)))
                new_t = threading.Thread(target=new_socket, args=(port, switch_server, mode,))
                new_t.start()
                sys.stderr.write("the socket has successfully connected to port {}\n".format(port))
            else:
                sys.stderr.write("error: send message in following format: > connect {port_number}\n")


if __name__ == '__main__':
    main(sys.argv)

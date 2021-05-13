from scapy.all import raw, struct
from scapy.fields import BitField, StrLenField
from scapy.packet import Packet
from pathlib import Path

import socket
import sys
import traceback
import os.path
import time

RUSHB_PROTOCOL_VERSION = "0.3"
"""
0.1 - Initial release
0.2 - Add *out file and fix bugs
0.3 - Add sleep for sending message
"""

LOCAL_HOST = "127.0.0.1"
RECV_SIZE = 4096
TIME_OUT = 5

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


class RUSH(Packet):
    name = "RUSH"
    fields_desc = [
        BitField("source_ip", 0, 32),
        BitField("destination_ip", 0, 32),
        BitField("offset", 0, 24),
        BitField("mode", 0, 8),
    ]


class RUSHIp(RUSH):
    name = "RUSH_IP"
    fields_desc = [
        BitField("ip", 0, 32),
    ]


class RUSHData(RUSH):
    name = "RUSH_DATA"
    fields_desc = [
        StrLenField("data", "", length_from=lambda x: x.length),
    ]


class RUSHLocation(RUSH):
    name = "RUSH_LOCATION"
    fields_desc = [
        BitField("x", 0, 16),
        BitField("y", 0, 16),
    ]


class RUSHDistance(RUSH):
    name = "RUSH_DISTANCE"
    fields_desc = [
        BitField("target_ip", 0, 32),
        BitField("distance", 0, 32),
    ]


def str_to_int(string):
    b_str = string.encode("UTF-8")
    return int.from_bytes(b_str, byteorder='big')


def int_to_str(integer, size=11):
    return integer.to_bytes(size, byteorder='big').decode("UTF-8")


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def build_packet(source_ip, destination_ip, offset, mode, misc=None):
    s_ip = ip_to_int(source_ip)
    d_ip = ip_to_int(destination_ip)
    try:
        pkt = RUSH(source_ip=s_ip, destination_ip=d_ip, offset=offset, mode=mode)
        if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            t_ip = ip_to_int(misc)
            additional = RUSHIp(ip=t_ip)
        elif mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
            additional = misc.encode('utf-8')
        elif mode == LOCATION:
            additional = RUSHLocation(x=misc[0], y=misc[1])
        elif mode is DISTANCE:
            t_ip = ip_to_int(misc[0])
            additional = RUSHDistance(target_ip=t_ip, distance=misc[1])
        else:
            additional = None
    except:
        traceback.print_exc(file=sys.stderr)
        assert False, f"There is a problem while building packet."
    return pkt, additional


def int_to_location(data):
    x = data & 0x11110000 >> 8
    y = data & 0x00001111
    return f'x = {x}, y = {y}'


def new_tcp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LOCAL_HOST, port))
    return sock


def new_udp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_HOST, port))
    return sock


def get_info_file(file_path, skip=0):
    info = None
    try:
        while not os.path.exists(file_path):
            time.sleep(1)
        if os.path.isfile(file_path):
            time.sleep(3)
            f = open(file_path, "r")
            for i in range(skip):
                f.readline()
            target_port = int(f.readline())
            info = (LOCAL_HOST, target_port)
    except:
        traceback.print_exc(file=sys.stderr)
        assert False, f"Error while getting the file."
    return info


class Connection:
    def __init__(self, output):
        self._my_sockets = []
        self._target_sockets = []
        self._output = output

    def _send(self, pkt, additional, sock, target_info=None, print_out=False, extend_message=""):
        time.sleep(0.2)
        try:
            message = raw(pkt)
            if additional is not None:
                message += raw(additional)
            if target_info is None:
                sock.sendall(message)
            else:
                sock.sendto(message, target_info)
            if print_out:
                self._print(pkt, additional, f"{extend_message}Sent: ")
        except:
            traceback.print_exc(file=sys.stderr)
            assert False, f"Error while sending a message to a socket."

    def _recv(self, sock, print_out=False, extend_message=""):
        try:
            raw_data, info = sock.recvfrom(RECV_SIZE)
        except:
            traceback.print_exc(file=sys.stderr)
            assert False, f"Error while receiving a message from a socket."
        try:
            mode = raw_data[11]
            pkt = RUSH(raw_data[:12])
            left_over = raw_data[12:]
            if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
                additional = RUSHIp(left_over)
            elif mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
                additional = left_over
            elif mode == LOCATION:
                additional = RUSHLocation(left_over)
            elif mode is DISTANCE:
                additional = RUSHDistance(left_over)
            else:
                pkt = RUSH(raw_data)
                additional = ""
            if print_out:
                self._print(pkt, additional, f"{extend_message}Received: ")
            return pkt, additional, info
        except:
            traceback.print_exc(file=sys.stderr)
            assert False, "Could not decode packet: " + repr(raw_data)

    def _print(self, pkt, additional, init=""):
        if pkt.mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            misc = f"assigned_ip={int_to_ip(additional.ip)}"
        elif pkt.mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
            misc = f"data={additional.decode('utf-8')}"
        elif pkt.mode is LOCATION:
            misc = f"x={additional.x}, y={additional.y}"
        elif pkt.mode is DISTANCE:
            misc = f"target_ip={int_to_ip(additional.target_ip)}, distance={additional.distance}"
        else:
            misc = "no_extra_data"
        output = f"{init}(source_ip={int_to_ip(pkt.source_ip)}, destination_ip={int_to_ip(pkt.destination_ip)}, " \
                        f"offset={pkt.offset}, mode={pkt.mode}, {misc})"
        self._output.write(output + "\n")
        self._output.flush()

    def close(self):
        for sock in self._target_sockets:
            sock.close()
        for sock in self._target_sockets:
            sock.close()

    def adapter_greeting(self, additional_message=""):
        # this test will stimulate a switch, user will execute the adapter and connect to the given port
        # the map of the connection:
        #
        #            [A] ----------------------> [T]
        #         ./RUSHBAdapter           Switch Stimulator
        #
        # [A] -> [T]
        # run the test using: python3 RUSHB.py -m ADAPTER_GREETING -o ADAPTER_GREETING.bout
        # check output using: diff ADAPTER_GREETING.bout test_files/ADAPTER_GREETING.bout
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        port = str(sock.getsockname()[1])
        sys.stdout.write(port + "\n")
        sys.stdout.flush()
        sys.stderr.write(f"New UDP port opened, run your adapter with these argument:\n\t[./RUSHBAdapter | java RUSHBAdapter | python3 RUSHBAdapter.py] {port}{additional_message}\n")
        sys.stderr.flush()
        data, add, info = self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="0.0.0.0", offset=0x000000, mode=OFFER, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=ACKNOWLEDGE, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        return sock, info

    def adapter_sending(self):
        # this test will stimulate a switch, establish the protocol as same as in adapter_greeting
        # then ask the adapter to send the input, using < test_files/ADAPTER_SENDING.ain
        # the map of the connection:
        #
        #            [A] ----------------------> [T]
        #         ./RUSHBAdapter           Switch Stimulator
        #
        # [A] -> [T]
        # run the test using: python3 RUSHB.py -m ADAPTER_SENDING -o ADAPTER_SENDING.bout
        # check output using: diff ADAPTER_SENDING.bout test_files/ADAPTER_SENDING.bout
        sock, info = self.adapter_greeting(additional_message=" < test_files/ADAPTER_SENDING.ain")
        self._recv(sock, print_out=True)
        return sock, info

    def adapter_receiving(self):
        # this test will stimulate a switch, establish the protocol as same as in adapter_greeting
        # the switch then sends a 0x05 message to the adapter, but will make a query protocol before sending it
        # the map of the connection:
        #
        #            [A] ----------------------> [T]
        #         ./RUSHBAdapter           Switch Stimulator
        #
        # [A] -> [T]
        # run the test using: python3 RUSHB.py -m ADAPTER_RECEIVING -o ADAPTER_RECEIVING.bout
        # check output using: diff ADAPTER_RECEIVING.bout test_files/ADAPTER_RECEIVING.bout
        #                     diff ADAPTER_RECEIVING.aout test_files/ADAPTER_RECEIVING.aout
        sock, info = self.adapter_greeting(additional_message=" > ADAPTER_RECEIVING.aout")
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=QUERY)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="130.102.71.65", destination_ip="192.168.1.2", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, sock, target_info=info, print_out=True)

    def adapter_fragmentation(self):
        # this test will stimulate a switch, establish the protocol as same as in ADAPTER_GREETING, user executes the adapter
        # the switch then sends 0x0a and 0x0b messages to the adapter after the query protocols
        # the map of the connection:
        #
        #            [A] ----------------------> [T]
        #         ./RUSHBAdapter           Switch Stimulator
        #
        # [A] -> [T]
        # run the test using: python3 RUSHB.py -m ADAPTER_FRAGMENTATION -o ADAPTER_FRAGMENTATION.bout
        # check output using: diff ADAPTER_FRAGMENTATION.bout test_files/ADAPTER_FRAGMENTATION.bout
        #                     diff ADAPTER_FRAGMENTATION.aout test_files/ADAPTER_FRAGMENTATION.aout
        sock, info = self.adapter_greeting(additional_message=" > ADAPTER_FRAGMENTATION.aout")
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=QUERY)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=MORE_FRAG, misc="a"*1488)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x0005d0, mode=MORE_FRAG, misc="b" * 1488)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000ba0, mode=END_FRAG, misc="c")
        self._send(pkt, add, sock, target_info=info, print_out=True)

    def adapter_wrong_receive(self):
        # this test will stimulate a switch, establish the protocol as same as in ADAPTER_GREETING, user executes the adapter
        # the switch then sends a 0x05 message to the adapter but the query protocol is somehow wrong
        # the map of the connection:
        #
        #            [A] ----------------------> [T]
        #         ./RUSHBAdapter           Switch Stimulator
        #
        # [A] -> [T]
        # run the test using: python3 RUSHB.py -m ADAPTER_WRONG_RECEIVE -o ADAPTER_WRONG_RECEIVE.bout
        # check output using: diff ADAPTER_WRONG_RECEIVE.bout test_files/ADAPTER_WRONG_RECEIVE.bout
        #                     diff ADAPTER_WRONG_RECEIVE.aout test_files/ADAPTER_WRONG_RECEIVE.aout
        sock, info = self.adapter_greeting(additional_message=" > ADAPTER_WRONG_RECEIVE.aout")
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=QUERY)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="130.102.71.65", destination_ip="192.168.1.2", offset=0x000000, mode=DATA,
                                misc="HELLO WORLD")
        self._send(pkt, add, sock, target_info=info, print_out=True)

    def switch_greeting_adapter(self):
        # this test will stimulate an adapter that sending greeting protocols to the target switch, user executes the switch
        # the switch has an IP address of 192.168.1.1/24 run in local mode
        # the map of the connection:
        #
        #            [A] ----------------------> [T]
        #     Adapter Stimulator           ./RUSHBSwitch
        #
        # [A] -> [T]
        # run the test using: python3 RUSHB.py -m SWITCH_GREETING_ADAPTER -o SWITCH_GREETING_ADAPTER.aout
        # check output using: diff SWITCH_GREETING_ADAPTER.aout test_files/SWITCH_GREETING_ADAPTER.aout
        file_path = "./SWITCH_GREETING_ADAPTER.bout"
        sys.stderr.write(
            f"Run your switch with these argument:\n\t[./RUSHBSwitch | java RUSHBSwitch | python3 RUSHBSwitch.py] local 192.168.1.1/24 0 2 > SWITCH_GREETING_ADAPTER.bout\n")
        sys.stderr.flush()
        info = get_info_file(file_path)
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)

    def _switch_offer(self, sock, target, host_ip, assigned_ip, location=(0, 0), switch_name="[S] "):
        try:
            self._recv(sock, print_out=True, extend_message=switch_name)
            pkt, add = build_packet(source_ip=host_ip, destination_ip="0.0.0.0", offset=0x000000, mode=OFFER, misc=assigned_ip)
            self._send(pkt, add, sock, target_info=target, print_out=True, extend_message=switch_name)
            self._recv(sock, print_out=True, extend_message=switch_name)
            pkt, add = build_packet(source_ip=host_ip, destination_ip=assigned_ip, offset=0x000000, mode=ACKNOWLEDGE, misc=assigned_ip)
            self._send(pkt, add, sock, target_info=target, print_out=True, extend_message=switch_name)
            self._recv(sock, print_out=True, extend_message=switch_name)
            pkt, add = build_packet(source_ip=host_ip, destination_ip=assigned_ip, offset=0x000000, mode=LOCATION, misc=location)
            self._send(pkt, add, sock, target_info=target, print_out=True, extend_message=switch_name)
        except:
            traceback.print_exc(file=sys.stderr)
            assert False, f"Error while receiving a message from a socket in switch offer."

    def switch_forward_message(self):
        # this test will stimulate an adapter and a switch in 2 side of target switch, user will executes the switch
        # the target switch has an IP address of 192.168.1.1/24 run in local mode
        # the map of the connection:
        #
        #            [A] ----------------------> [T] ----------------------> [S]
        #     Adapter Stimulator           ./RUSHBSwitch               Switch Stimulator
        #
        # [A] -> [T], [T] -> [S], [A] sends a message that need [T] to transfer to [S]
        # run the test using: python3 RUSHB.py -m SWITCH_FORWARD_MESSAGE -o SWITCH_FORWARD_MESSAGE.bout
        # check output using: diff SWITCH_FORWARD_MESSAGE.bout test_files/SWITCH_FORWARD_MESSAGE.bout
        tcp_sock = new_tcp_socket(0)  # tcp connection
        self._my_sockets.append(tcp_sock)
        port = str(tcp_sock.getsockname()[1])
        with open("./SWITCH_FORWARD_MESSAGE.b2in", "w+") as port_writer:
            port_writer.write(f"connect {str(port)}\n")
            port_writer.flush()
        sys.stderr.write(
            f"Run your switch with these argument:\n\t[./RUSHBSwitch | java RUSHBSwitch | python3 RUSHBSwitch.py] local 192.168.1.1/24 0 2 < SWITCH_FORWARD_MESSAGE.b2in > SWITCH_FORWARD_MESSAGE.b2out\n")
        sys.stderr.flush()
        tcp_sock.listen()
        conn, addr = tcp_sock.accept()
        self._target_sockets.append(conn)
        switch_name = "[S] "
        self._switch_offer(conn, addr, host_ip="130.0.0.1", assigned_ip="130.0.0.2", switch_name=switch_name)
        pkt, add = build_packet(source_ip="130.0.0.1", destination_ip="130.0.0.2", offset=0x000000, mode=DISTANCE, misc=("20.0.0.1", 10))
        self._send(pkt, add, conn, target_info=addr, print_out=True, extend_message=switch_name)

        udp_sock = new_udp_socket(0)  # udp connection
        self._my_sockets.append(udp_sock)
        adapter_name = "[A] "
        file_path = "SWITCH_FORWARD_MESSAGE.b2out"
        info = get_info_file(file_path)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="192.168.1.2", destination_ip="135.0.0.1", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        # tcp connection
        self._recv(conn, print_out=True, extend_message=switch_name)
        pkt, add = build_packet(source_ip="130.0.0.1", destination_ip="130.0.0.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, conn, target_info=info, print_out=True, extend_message=switch_name)
        self._recv(conn, print_out=True, extend_message=switch_name)

    def switch_distance_switch(self, modified_test_name="SWITCH_DISTANCE_SWITCH"):
        # this test will stimulate 2 switch connect 2 side of the target switch, user will executes the switch
        # the target switch has an IP address of 192.168.1.1/24 run in local mode
        # the map of the connection:
        #
        #            [S1] <---------------------- [T] ----------------------> [S2]
        #        Switch Stimulator 1         ./RUSHBSwitch               Switch Stimulator 2
        #
        # [T] connects to [S1], then [S2], [T] send its new neighbourhood ([S2]) to [S1]
        # run the test using: python3 RUSHB.py -m SWITCH_DISTANCE_SWITCH -o SWITCH_DISTANCE_SWITCH.bout
        # check output using: diff SWITCH_DISTANCE_SWITCH.bout test_files/SWITCH_DISTANCE_SWITCH.bout
        tcp_sock_1 = new_tcp_socket(0)  # sock 1
        self._my_sockets.append(tcp_sock_1)
        port_1 = str(tcp_sock_1.getsockname()[1])

        tcp_sock_2 = new_tcp_socket(0)  # sock 2
        self._my_sockets.append(tcp_sock_2)
        port_2 = str(tcp_sock_2.getsockname()[1])
        with open(f"./{modified_test_name}.b2in", "w+") as port_writer:
            port_writer.write(f"connect {str(port_1)}\nconnect {str(port_2)}\n")
            port_writer.flush()

        sys.stderr.write(
            f"Run your switch with these argument:\n\t[./RUSHBSwitch | java RUSHBSwitch | python3 RUSHBSwitch.py] local 192.168.1.1/24 0 2 < {modified_test_name}.b2in > {modified_test_name}.b2out\n")
        sys.stderr.flush()
        tcp_sock_1.listen()
        conn_1, addr_1 = tcp_sock_1.accept()
        self._target_sockets.append(conn_1)
        switch_1_name = "[S1] "
        self._switch_offer(conn_1, addr_1, host_ip="135.0.0.1", assigned_ip="135.0.0.2", location=(0, 0), switch_name=switch_1_name)

        tcp_sock_2.listen()
        conn_2, addr_2 = tcp_sock_2.accept()
        self._target_sockets.append(conn_2)
        switch_2_name = "[S2] "
        self._switch_offer(conn_2, addr_2, host_ip="136.0.0.1", assigned_ip="136.0.0.2", location=(0, 4), switch_name=switch_2_name)
        self._recv(conn_1, print_out=True, extend_message=switch_1_name)
        return (conn_1, addr_1), (conn_2, addr_2)

    def switch_routing_simple(self, test_name="SWITCH_ROUTING_SIMPLE", data_destination="134.0.0.1", d1=3, d2=5):
        # this test will stimulate 2 switches and an adapter that connecting to the target switch, user executes a switch
        # the target switch has an IP address of 192.168.1.1/24 run in local mode
        # the map of the connection:
        #
        #            [S1] <---------------------- [T] ----------------------> [S2]
        #        Switch Stimulator 1         ./RUSHBSwitch               Switch Stimulator 2
        #                                          ^
        #                                         [A]
        #                                    Adapter Stimulator
        #
        # [T] connects to [S1], then [S2], there will be some distance exchanges, then [A] will send a message
        # run the test using: python3 RUSHB.py -m SWITCH_ROUTING_SIMPLE -o SWITCH_ROUTING_SIMPLE.bout
        # check output using: diff SWITCH_ROUTING_SIMPLE.bout test_files/SWITCH_ROUTING_SIMPLE.bout
        info_1, info_2 = self.switch_distance_switch(modified_test_name=test_name)
        switch_1_name = "[S1] "
        switch_2_name = "[S2] "
        # [S1] -> [T] : D([S3])
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=DISTANCE, misc=("134.0.0.1", d1))
        self._send(pkt, add, info_1[0], target_info=info_1[1], print_out=True, extend_message=switch_1_name)
        # [T] -> [S2] : D([S3])
        self._recv(info_2[0], print_out=True, extend_message=switch_2_name)
        # [S2] -> [T] : D([S3])
        pkt, add = build_packet(source_ip="136.0.0.1", destination_ip="136.0.0.2", offset=0x000000, mode=DISTANCE, misc=("134.0.0.1", d2))
        self._send(pkt, add, info_2[0], target_info=info_2[1], print_out=True, extend_message=switch_2_name)
        # [T] -> [S1] : D([S3])
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)
        # [A] -> [T] : "HELLO WORLD"
        udp_sock = new_udp_socket(0)  # udp connection
        self._my_sockets.append(udp_sock)
        adapter_name = "[A] "
        file_path = f"{test_name}.b2out"
        info = get_info_file(file_path)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="192.168.1.2", destination_ip=data_destination, offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        # [T] -> [S1]
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, info_1[0], target_info=info, print_out=True, extend_message=switch_1_name)
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)

    def switch_routing_prefix(self):
        # this test will stimulate 2 switches and an adapter that connecting to the target switch, user executes a switch
        # the target switch has an IP address of 192.168.1.1/24 run in local mode
        # the map of the connection:
        #
        #            [S1] <---------------------- [T] ----------------------> [S2]
        #        Switch Stimulator 1         ./RUSHBSwitch               Switch Stimulator 2
        #                                          ^
        #                                         [A]
        #                                    Adapter Stimulator
        #
        # [T] connects to [S1], then [S2], there will be some distance exchanges, then [A] will send a message but
        # the destination address is not in T's database
        # run the test using: python3 RUSHB.py -m SWITCH_ROUTING_PREFIX -o SWITCH_ROUTING_PREFIX.bout
        # check output using: diff SWITCH_ROUTING_PREFIX.bout test_files/SWITCH_ROUTING_PREFIX.bout
        self.switch_routing_simple(test_name="SWITCH_ROUTING_PREFIX", data_destination="129.0.0.1", d1=5, d2=3)


ADAPTER_GREETING = [Connection.adapter_greeting]
ADAPTER_SENDING = [Connection.adapter_sending]
ADAPTER_RECEIVING = [Connection.adapter_receiving]
ADAPTER_FRAGMENTATION = [Connection.adapter_fragmentation]
ADAPTER_WRONG_RECEIVE = [Connection.adapter_wrong_receive]

SWITCH_GREETING_ADAPTER = [Connection.switch_greeting_adapter]
SWITCH_FORWARD_MESSAGE = [Connection.switch_forward_message]
SWITCH_DISTANCE_SWITCH = [Connection.switch_distance_switch]

SWITCH_ROUTING_SIMPLE = [Connection.switch_routing_simple]
SWITCH_ROUTING_PREFIX = [Connection.switch_routing_prefix]


def main(argv):
    for p in Path(".").glob("*out"):
        p.unlink()
    time.sleep(1)

    sys.stdout.write('RUSHB_PROTOCOL_VERSION: ' + RUSHB_PROTOCOL_VERSION + '\n')
    sys.stdout.flush()

    mode = ADAPTER_GREETING
    output = sys.stdout

    for i, arg in enumerate(argv[1:]):
        if arg == "-m":
            mode = {'ADAPTER_GREETING': ADAPTER_GREETING,
                    'ADAPTER_SENDING': ADAPTER_SENDING,
                    'ADAPTER_RECEIVING': ADAPTER_RECEIVING,
                    'ADAPTER_FRAGMENTATION': ADAPTER_FRAGMENTATION,
                    'ADAPTER_WRONG_RECEIVE': ADAPTER_WRONG_RECEIVE,
                    'SWITCH_GREETING_ADAPTER': SWITCH_GREETING_ADAPTER,
                    'SWITCH_FORWARD_MESSAGE': SWITCH_FORWARD_MESSAGE,
                    'SWITCH_DISTANCE_SWITCH': SWITCH_DISTANCE_SWITCH,
                    'SWITCH_ROUTING_SIMPLE': SWITCH_ROUTING_SIMPLE,
                    'SWITCH_ROUTING_PREFIX': SWITCH_ROUTING_PREFIX
                    }.get(argv[i + 2].upper(), ADAPTER_GREETING)
        elif arg == '-o':
            output = open(argv[i + 2], "w")

    conn = Connection(output)

    try:
        for method in mode:
            method(conn)
    except AssertionError as e:
        print(e.args[0])
    conn.close()

    if output != sys.stdout:
        output.close()

    sys.stderr.write('Test finished, now you can check the output file.\n')
    sys.stderr.flush()


if __name__ == "__main__":
    main(sys.argv)

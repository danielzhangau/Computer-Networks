import socket
import sys
from scapy.packet import Packet
from scapy.fields import ByteField, ShortField, BitField
from scapy.all import raw
import time
import random 


RUSHB_TESTCLIENT_VERSION = "1.1"
'''
0.1 - initial release
0.2 - fix bug of encrypting
0.3 - fix bug of bytes ordering
0.4 - fix checksum mode
0.5 - fix bug of encrypting in decoding
1.0 - official sample client
1.1 - update to match with the rep client
'''

LOCALHOST = "127.0.0.1"
FILE_NAME = "files/file.txt"

PACKET_SIZE = 1472
PAYLOAD_SIZE = 1464
PAYLOAD_SIZE_BITS = PAYLOAD_SIZE * 8

RECV_SIZE = 1500

ENC_KEY = 11
DEC_KEY = 15
MOD = 249

SEND_MODE = "Sent packet to"
RECV_MODE = "Received packet from"


def str_to_int(string, pad=PAYLOAD_SIZE):
    b_str = string
    if pad is not None:
        for i in range(len(string), pad):
            b_str += b'\0'
    return int.from_bytes(b_str, byteorder='big')


def int_to_bytes(integer, size=PAYLOAD_SIZE):
    return integer.to_bytes(size, byteorder='big').rstrip(b'\x00')


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):        
        w = b_str[i] + (b_str[i+1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff


def encode(payload, key=ENC_KEY, n=MOD):
    result = b""
    for c in payload:
        result += ((ord(c) ** key) % n).to_bytes(1, 'big')
    return result


class RUSH(Packet):
    name = "RUSH"
    fields_desc = [
        ShortField("seq_num", 0),
        ShortField("ack_num", 0),
		ShortField("checksum", 0),
        BitField("ack_flag", 0, 1),
        BitField("nak_flag", 0, 1),
        BitField("get_flag", 0, 1),
        BitField("dat_flag", 0, 1),
        BitField("fin_flag", 0, 1),
		BitField("chk_flag", 0, 1),
		BitField("enc_flag", 0, 1),
        BitField("reserved", 0, 6),
		BitField("version", 2, 3),  #RUSHB packet version
        BitField("data", 0, PAYLOAD_SIZE_BITS)
    ]


class Connection:
    def __init__(self, my_ip, my_port, serv_ip, serv_port, output=sys.stdout, debug_level=1):
        self._my_info = (my_ip, my_port)
        self._serv_info = (serv_ip, serv_port)
        self._socket = None
        self._seq_num = 1
        self._chk_flag = 0
        self._enc_flag = 0
        self._output = output
        self._debug_level = debug_level
        self._start_time = time.time()

    def _print(self, pkt, port, mode, note=""):
        output = ""
        timer = round(time.time() - self._start_time, 4)
        if self._debug_level > 0:
            output += "{} port{}{}:\n    (seq_num={}, ack_num={}, checksum={}, flags={}{}{}{}{}{}{}) {}".format(mode, 
                        " " + str(port) if self._debug_level != 9 else "", 
                        " at {}s".format(timer) if self._debug_level in (2, 3) else "",
                        pkt.seq_num, pkt.ack_num, pkt.checksum, pkt.ack_flag, pkt.nak_flag, pkt.get_flag, pkt.dat_flag, pkt.fin_flag, pkt.chk_flag, pkt.enc_flag,
                        note if self._debug_level != 9 else "")
        if self._debug_level in (3, 9):
            if not pkt.enc_flag:
                output += "\n    Data: {}".format(repr(int_to_bytes(pkt.data).decode("UTF-8")))
            else:
                output += "\n    Data: {}".format(repr(int_to_bytes(pkt.data)))
        self._output.write(output + "\n\n")

    def connect(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind(self._my_info)
            return True
        except socket.error as err:
            print("Error encountered when opening socket:\n", err)
            return False

    def close(self):
        self._socket.close()

    def enc(self):
        self._enc_flag = 1

    def chk(self):
        self._chk_flag = 1

    def _send(self, pkt, mode, note, data='', key=ENC_KEY, checksum_error=""):
        payload = encode(data, key) if self._enc_flag else data.encode('ascii')
        pkt.data = str_to_int(payload)
        new_payload = payload + str.encode(checksum_error)
        pkt.checksum = compute_checksum(new_payload) if self._chk_flag else 0x0000
        self._socket.sendto(raw(pkt), self._serv_info)
        self._print(pkt, self._serv_info[1], mode, note=note)

    def send_request(self, resource=FILE_NAME, key=ENC_KEY, checksum_error="", note="[GET]"):
        pkt = RUSH(seq_num=self._seq_num, get_flag=1, enc_flag=self._enc_flag, chk_flag=self._chk_flag)
        self._send(pkt, SEND_MODE, note, data=resource, key=key, checksum_error=checksum_error)
        self._seq_num += 1

    def recv_pkt(self):
        raw_data, info = self._socket.recvfrom(RECV_SIZE)
        assert len(raw_data) <= PACKET_SIZE, "Received overlong packet: " + repr(raw_data)
        try:
            pkt = RUSH(raw_data)
        except:
            assert False, "Could not decode packet: " + repr(raw_data)
       
        assert self._chk_flag == pkt.chk_flag, "Checksum flag error:" + repr(pkt.chk_flag)
        assert self._enc_flag == pkt.enc_flag, "Encode flag error:" + repr(pkt.enc_flag)
        data = int_to_bytes(pkt.data)
        assert (pkt.checksum == compute_checksum(data)) if self._chk_flag else (pkt.checksum == 0), "Checksum value error."
        return pkt, info

    def nak(self):
        pkt, info = self.recv_pkt()
        self._print(pkt, info[1], RECV_MODE)
        nak = RUSH(seq_num=self._seq_num, ack_num=1, dat_flag=1, nak_flag=1, enc_flag=self._enc_flag, chk_flag=self._chk_flag)
        self._send(nak, SEND_MODE, '[NAK]')
        self._seq_num += 1

    def timeout(self):
        pkt, info = self.recv_pkt()
        self._print(pkt, info[1], RECV_MODE)
        # let the server timeout by doing nothing

    def invalid_flags(self):
        """Invalid because the server should be expecting an ACK or a NAK, not a get"""
        pkt, info = self.recv_pkt()
        self._print(pkt, info[1], RECV_MODE)
        invalid: RUSH = RUSH(seq_num=self._seq_num, ack_num=1, get_flag=1, enc_flag=self._enc_flag, chk_flag=self._chk_flag)
        self._send(invalid, SEND_MODE, '[INVALID_FLAGS]')

    def invalid_seq(self):
        """Invalid because the server is expecting a packet with sequence number 2"""
        pkt, info = self.recv_pkt()
        self._print(pkt, info[1], RECV_MODE)
        invalid = RUSH(seq_num=self._seq_num+1, ack_num=1, dat_flag=1, ack_flag=1, enc_flag=self._enc_flag, chk_flag=self._chk_flag)
        self._send(invalid, SEND_MODE, '[INVALID_SEQ]')

    def invalid_ack(self):
        """Invalid because the server is expecting a packet acknowledging packet 1"""
        pkt, info = self.recv_pkt()
        self._print(pkt, info[1], RECV_MODE)
        invalid = RUSH(seq_num=self._seq_num, ack_num=2, dat_flag=1, ack_flag=1, enc_flag=self._enc_flag, chk_flag=self._chk_flag)
        self._send(invalid, SEND_MODE, '[INVALID]')

    def send_invalid_checksum_request(self):
        """Invalid because incorrect checksum value"""
        self.send_request(key=ENC_KEY, checksum_error="ERROR", note="[INVALID CHK GET]")
        time.sleep(1)
        self._seq_num = 1

    def send_invalid_encode_request(self):
        """Invalid because incorrect encode key value"""
        self.send_request(key=(ENC_KEY ** 5 + 2), checksum_error="", note="[INVALID ENC GET]")
    
    def invalid_enc_chk_flags(self, enc_flag, chk_flag):
        """Invalid because enc/chk flags is/are invalid"""
        pkt, info = self.recv_pkt()
        self._print(pkt, info[1], RECV_MODE)
        invalid = RUSH(seq_num=self._seq_num, ack_num=pkt.seq_num, dat_flag=1, ack_flag=1, enc_flag=enc_flag, chk_flag=chk_flag)
        self._send(invalid, SEND_MODE, '[INVALID]')
    
    def invalid_enc_flag(self):
        error_enc_flag = 0 if self._enc_flag else 1
        self.invalid_enc_chk_flags(enc_flag=error_enc_flag, chk_flag=self._chk_flag)

    def invalid_chk_flag(self):
        error_chk_flag = 0 if self._chk_flag else 1
        self.invalid_enc_chk_flags(enc_flag=self._enc_flag, chk_flag=error_chk_flag)

    def run(self):
        while True:
            pkt, info = self.recv_pkt()
            self._print(pkt, info[1], RECV_MODE)
            if pkt.fin_flag == 1 and all(i == 0 for i in (pkt.ack_flag, pkt.nak_flag, pkt.dat_flag, pkt.get_flag)):
                cli_fin_ack = RUSH(seq_num=self._seq_num, ack_num=pkt.seq_num, fin_flag=1, ack_flag=1, enc_flag=self._enc_flag, chk_flag=self._chk_flag)
                self._send(cli_fin_ack, SEND_MODE, '[FIN/ACK]')
                self._seq_num += 1

                while True:
                    serv_fin_ack, info = self.recv_pkt()
                    self._print(serv_fin_ack, info[1], RECV_MODE)
                    if serv_fin_ack.fin_flag == 1 and serv_fin_ack.ack_flag == 1 and \
                            all(i == 0 for i in (serv_fin_ack.nak_flag, serv_fin_ack.dat_flag, serv_fin_ack.get_flag)):
                        return  # end of connection
            elif pkt.dat_flag == 1:
                ack = RUSH(seq_num=self._seq_num, ack_num=pkt.seq_num, dat_flag=1, ack_flag=1, enc_flag=self._enc_flag, chk_flag=self._chk_flag)
                self._send(ack, SEND_MODE, '[ACK]')
                self._seq_num += 1


SIMPLE_MODE = [Connection.send_request, Connection.run]
NAK_MODE = [Connection.send_request, Connection.nak, Connection.run]
MULTI_NAK_MODE = [Connection.send_request, Connection.nak, Connection.nak, Connection.nak, Connection.run]
TIMEOUT_MODE = [Connection.send_request, Connection.timeout, Connection.run]
MULTI_TIMEOUT_MODE = [Connection.send_request, Connection.timeout, Connection.nak, Connection.timeout, Connection.run]
INVALID_SEQ_MODE = [Connection.send_request, Connection.invalid_seq, Connection.run]
INVALID_ACK_MODE = [Connection.send_request, Connection.invalid_ack, Connection.run]
INVALID_FLAGS_MODE = [Connection.send_request, Connection.invalid_flags, Connection.run]

ENCODED_MODE = [Connection.enc, Connection.send_request, Connection.run]
CHECKSUM_MODE = [Connection.chk, Connection.send_request, Connection.run]
ENCODED_CHECKSUM_MODE = [Connection.enc, Connection.chk, Connection.send_request, Connection.run]

INVALID_ENCODE_VAL_MODE = [Connection.enc, Connection.send_invalid_encode_request, Connection.run]
INVALID_CHECKSUM_VAL_MODE = [Connection.chk, Connection.send_invalid_checksum_request, Connection.send_request, Connection.run]

INVALID_ENCODE_FLAG_MODE = [Connection.enc, Connection.send_request, Connection.invalid_enc_flag, Connection.run]
INVALID_CHECKSUM_FLAG_MODE = [Connection.chk, Connection.send_request, Connection.invalid_chk_flag, Connection.run]


def main(argv):
    print('RUSHB_CLIENT_VERSION: ' + RUSHB_TESTCLIENT_VERSION)
    if len(argv) <= 2 or not argv[1].isdigit() or not argv[2].isdigit():
        print("Usage: python3 RUSHBSimpleClient.py client_port server_port [-v] [-m mode] [-o output]")
        return

    my_port = int(argv[1])
    serv_port = int(argv[2])

    debug_level = 2
    mode = SIMPLE_MODE
    output = sys.stdout
    for i, arg in enumerate(argv[3:]):
        if arg == "-v" and argv[i + 4] in ("0", "1", "2", "3", "9", "10"):
            debug_level = int(argv[i + 4])
        elif arg == "-m":
            mode = {"SIMPLE": SIMPLE_MODE, "NAK": NAK_MODE, "MULTI_NAK": MULTI_NAK_MODE, "TIMEOUT": TIMEOUT_MODE,
                    "MULTI_TIMEOUT": MULTI_TIMEOUT_MODE, "INVALID_SEQ": INVALID_SEQ_MODE,
                    "INVALID_ACK": INVALID_ACK_MODE, "INVALID_FLAGS": INVALID_FLAGS_MODE,
                    "ENCODED": ENCODED_MODE, "CHECKSUM": CHECKSUM_MODE, "ENCODED_CHECKSUM": ENCODED_CHECKSUM_MODE,
                    "INVALID_ENCODE_VAL": INVALID_ENCODE_VAL_MODE, "INVALID_CHECKSUM_VAL": INVALID_CHECKSUM_VAL_MODE,
                    "INVALID_ENCODE_FLAG": INVALID_ENCODE_FLAG_MODE, "INVALID_CHECKSUM_FLAG": INVALID_CHECKSUM_FLAG_MODE
                    }.get(argv[i+4].upper(), SIMPLE_MODE)
        elif arg == "-o":
            output = open(argv[i+4], "w")

    conn = Connection(LOCALHOST, my_port, LOCALHOST, serv_port, output, debug_level)

    if not conn.connect():
        return

    try:
        for method in mode:
            if debug_level in (3, 9, 10):
                print(':::: ' + method.__name__)
            method(conn)
    except AssertionError as e:
        print(e.args[0])
    print(':::: finished')
    conn.close()
    if output != sys.stdout:
        output.close()


if __name__ == "__main__":
    main(sys.argv)


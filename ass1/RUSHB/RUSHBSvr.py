# Import the socket and datetime module
import socket
import sys

LOCALIP = "127.0.0.1"

RECV_SIZE = 1500
PAYLOAD_SIZE = 1464
PAYLOAD_SIZE_BITS = PAYLOAD_SIZE * 8

ENC_KEY = 11
DEC_KEY = 15
MOD = 249

# acknowledgement (ACK), The flag is set if the acknowledgement number field contains a valid acknowledgement number.
# negative-acknowledgement (NAK),
# finish (FIN), It is used to request for connection termination
GET = '0010000'
DAT = '0001000'
FIN = '0000100'
DAT_ACK = '1001000'
DAT_NAK = '0101000'
ACK_FIN = '1000100'

GET_SUM = '0010010'
DAT_SUM = '0001010'
FIN_SUM = '0000110'
DAT_ACK_SUM = '1001010'
DAT_NAK_SUM = '0101010'
ACK_FIN_SUM = '1000110'

GET_ENC = '0010001'
DAT_ENC = '0001001'
FIN_ENC = '0000101'
DAT_ACK_ENC = '1001001'
DAT_NAK_ENC = '0101001'
ACK_FIN_ENC = '1000101'

GET_SUM_ENC = '0010011'
DAT_SUM_ENC = '0001011'
FIN_SUM_ENC = '0000111'
DAT_ACK_SUM_ENC = '1001011'
DAT_NAK_SUM_ENC = '0101011'
ACK_FIN_SUM_ENC = '1000111'


def str_to_int(string, pad=PAYLOAD_SIZE):
    """ To convert a string to integer """
    b_str = string.encode("UTF-8")
    if pad is not None:
        for i in range(len(string), pad):
            b_str += b'\0'
    return int.from_bytes(b_str, byteorder='big')


def encryption(payload, key=ENC_KEY, n=MOD):
    result = b""
    for c in payload:
        result += ((ord(c) ** key) % n).to_bytes(1, 'big')
    return result


def decryption(payload, key=DEC_KEY, n=MOD):
    result = ""
    for c in payload:
        result += chr((c ** key) % n)
    return result


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):
        w = b_str[i] + (b_str[i + 1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff


class UDPServer:
    """ A simple UDP Server """

    def __init__(self, host):
        self._host = host  # Host address
        self._socket = None  # Socket
        self._packet = b''
        self._file = ''
        self._client_seq = 0
        self._seq = 0
        self._chk_sum = 0  # if 1 means do for rest
        self._encoded = 0  # if 1 means do for rest
        self._encoded_err = 0  # if i means have error

    def configure_server(self):
        """ Configure the server """
        # create UDP socket with IPv4 addressing
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # bind server to the address
        self._socket.bind((self._host, 0))
        ip, port = self._socket.getsockname()
        print(port)
        sys.stdout.flush()

    def recv_pkt(self):
        """action when the server receives a client’s file request """
        while True:
            # has sent packet before
            if self._packet:
                try:
                    message, address = self._socket.recvfrom(RECV_SIZE)
                except socket.timeout:
                    self.retrans_packet(address)
                    continue
            else:
                message, address = self._socket.recvfrom(RECV_SIZE)

            seq_num = int.from_bytes(message[:2], byteorder='big')
            ack_num = int.from_bytes(message[2:4], byteorder='big')
            chk_sum = int.from_bytes(message[4:6], byteorder='big')
            fourth_line = bin(int.from_bytes(message[6:8], byteorder='big'))[2:].zfill(16)
            flags = fourth_line[:7]
            reserved = fourth_line[7:13]
            version = fourth_line[13:16]
            print("seq_num={}, ack_num={}, checksum={}, flags={}, reserved={}, version={}) "
                  "{}".format(seq_num, ack_num, chk_sum, flags, reserved, version, message[8:]))
            if all([c == '0' for c in reserved]):
                # The server receives the [GET] message, then transmits the requested resource to the
                # client over (possibly) multiple [DAT] packets.
                # if CHECKSUM flag is on
                if (flags[5] == '1') | (self._chk_sum == 1):
                    if (self._chk_sum == 1) & (flags[5] != '1'):  # invalid flag
                        continue
                    elif compute_checksum(message[8:]) == chk_sum:
                        print(compute_checksum(message[8:]))
                        self._chk_sum = 1
                    else:
                        continue

                if (self._encoded == 1) & (flags[6] != '1'):  # invalid flag
                    continue

                if (flags == GET) | (flags == GET_SUM) | (flags == GET_ENC) | (flags == GET_SUM_ENC):  # GET
                    if seq_num == 1 and ack_num == 0:
                        # if ENCODED flag is on
                        if (flags[6] == '1') | (self._encoded == 1):
                            if (self._encoded == 1) & (flags[6] != '1'):  # invalid flag
                                continue
                            else:
                                file_name = decryption(message[8:]).encode().rstrip(b'\x00')
                                # print("file_name: ", file_name)
                                self._encoded = 1
                        else:
                            file_name = self.get_file_name(message[8:])
                            # print("file_name: ", file_name)
                        if file_name:  # means having the file
                            self._file = self.read_file(file_name)
                            if self._file is None:
                                self._encoded_err = 1
                            print("file content: ", self._file)
                            self.trans_packet(address, seq_num, self._chk_sum, self._encoded, self._encoded_err)
                elif (flags == DAT_ACK) | (flags == DAT_ACK_SUM) | (flags == DAT_ACK_ENC) | (
                        flags == DAT_ACK_SUM_ENC):  # DAT/ACK
                    if self.check_num(seq_num, ack_num) and not self.get_file_name(message[8:]):
                        # The client acknowledges having received each data packet
                        if len(self._file) > 0:
                            self.trans_packet(address, seq_num, self._chk_sum, self._encoded)
                        else:  # After receiving the last acknowledgement [DAT/ACK] from the client,
                            # the server send [FIN] message to end the connection
                            self._seq += 1
                            flags = FIN_SUM if self._chk_sum == 1 else FIN
                            if self._encoded:
                                if self._chk_sum:
                                    flags = FIN_SUM_ENC
                                else:
                                    flags = FIN_ENC
                            self._packet = self.make_packet(self._seq, 0, self._chk_sum, self._encoded, flags)
                            self._socket.sendto(self._packet, address)
                            self._client_seq = seq_num
                elif (flags == DAT_NAK) | (flags == DAT_NAK_SUM) | (flags == DAT_NAK_ENC) | (
                        flags == DAT_NAK_SUM_ENC):  # DAT/NAK
                    if self.check_num(seq_num, ack_num) and not self.get_file_name(message[8:]):
                        if self._packet:
                            self.retrans_packet(address)
                            self._client_seq = seq_num
                elif (flags == ACK_FIN) | (flags == ACK_FIN_SUM) | (flags == ACK_FIN_ENC) | (
                        flags == ACK_FIN_SUM_ENC):  # ACK/FIN
                    # After receiving the last acknowledgement [FIN/ACK] from the client,
                    # the server send [FIN/ACK] again to the client and close the connection.
                    if self.check_num(seq_num, ack_num) and not self.get_file_name(message[8:]):
                        self._seq += 1
                        flags = ACK_FIN_SUM if self._chk_sum == 1 else ACK_FIN
                        if self._encoded:
                            if self._chk_sum:
                                flags = ACK_FIN_SUM_ENC
                            else:
                                flags = ACK_FIN_ENC
                        self._packet = self.make_packet(self._seq, seq_num, self._chk_sum, self._encoded,
                                                        flags)  # ack == seq
                        self._socket.sendto(self._packet, address)
                        self._socket.close()
                        sys.exit()

    def trans_packet(self, addr, seq_num, chk_sum_flag, enc_flag, encoded_err=0):
        self._socket.settimeout(None)  # timeout applies to a single call to socket read/write operation.
        self._seq += 1  # subsequent packets should have a sequence number of 1 higher than the previous packet
        flags = DAT_SUM if chk_sum_flag else DAT
        if enc_flag:
            if chk_sum_flag:
                flags = DAT_SUM_ENC
            else:
                flags = DAT_ENC
        if encoded_err:
            flags = FIN_ENC
            self._packet = self.make_packet(self._seq, 0, chk_sum_flag, enc_flag, flags)
        else:
            self._packet = self.make_packet(self._seq, 0, chk_sum_flag, enc_flag, flags, self._file[:PAYLOAD_SIZE])
            self._file = self._file[PAYLOAD_SIZE:]
        self._socket.sendto(self._packet, addr)
        self._client_seq = seq_num
        self._socket.settimeout(3)

    def check_num(self, seq, ack):
        """ seq have to be 1 higher and the ack number is equal to the seq number """
        return seq == self._client_seq + 1 and ack == self._seq

    def retrans_packet(self, addr):
        self._socket.sendto(self._packet, addr)
        self._socket.settimeout(3)

    @staticmethod
    def make_packet(seq_num, ack_num, chk_sum_flag, enc_flag, flags, file=None):
        """ make packet with same style of packet received """
        if file is None:
            payload = (0).to_bytes(PAYLOAD_SIZE, byteorder='big')
        else:
            if (flags == GET_ENC) | (flags == GET_SUM_ENC):
                payload = encryption(file)
            else:
                payload = str_to_int(file).to_bytes(PAYLOAD_SIZE, byteorder='big')  # ascii payload
            print("payload: ", payload)
        chk_sum = compute_checksum(payload) if chk_sum_flag == 1 else 0
        header = ''
        header += bin(seq_num)[2:].zfill(16)  # ip header
        header += bin(ack_num)[2:].zfill(16)  # udp header
        header += bin(chk_sum)[2:].zfill(16)  # rushb header
        header += flags.ljust(13, '0')
        header += '010'  # version bits
        # print("header: ", header)
        return bytes([int(header[i:i + 8], 2) for i in range(0, 64, 8)]) + payload

    @staticmethod
    def get_file_name(ascii_payload):
        return ascii_payload.rstrip(b'\x00')

    @staticmethod
    def read_file(file_name):
        try:
            f = open(file_name, 'r')
        except EnvironmentError:
            return
        file = f.read()
        f.close()
        return file


def main():
    """ Create a UDP Server and respond to a client's resquest """
    udp_server = UDPServer(LOCALIP)
    udp_server.configure_server()
    udp_server.recv_pkt()


if __name__ == '__main__':
    main()

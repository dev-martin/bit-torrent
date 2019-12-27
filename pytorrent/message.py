from enum import Enum
from struct import pack, unpack
import logging
import config

PROTOCOL = b"BitTorrent protocol"
PROTOCOL_LEN = len(PROTOCOL)
RESERVED = b'\x00' * 8


class Message:
    def hton(self):
        raise NotImplementedError()

    @classmethod
    def ntoh(cls, payload):
        raise NotImplementedError()


class Handshake(Message):
    payload_length = total_length = 68

    def __init__(self, info_hash, peer_id=b'-ZZ0007-000000000000'):
        super(Handshake, self).__init__()

        assert len(peer_id) < 255
        self.peer_id = peer_id
        self.info_hash = info_hash

    def hton(self):
        handshake = pack(">B{}s8s20s20s".format(PROTOCOL_LEN),
                         PROTOCOL_LEN,
                         PROTOCOL,
                         RESERVED,
                         self.info_hash,
                         self.peer_id)

        return handshake

    @classmethod
    def ntoh(cls, payload):
        pstrlen, = unpack(">B", payload[:1])
        pstr, reserved, info_hash, peer_id = unpack(">{}s8s20s20s".format(pstrlen), payload[1:cls.total_length])

        if pstr != PROTOCOL:
            raise ValueError("Invalid string identifier of the protocol")

        return Handshake(info_hash.hex(), peer_id.decode('ascii'))


class Choke(Message):
    payload_length = 1

    def __init__(self):
        super(Choke, self).__init__()

    def hton(self):
        message = pack(">IB", self.payload_length, MessageID.choke.value)

        return message

    @classmethod
    def ntoh(cls, payload):
        raise NotImplementedError()


class UnChoke(Message):
    payload_length = 1

    def __init__(self):
        super(UnChoke, self).__init__()

    def hton(self):
        message = pack(">IB", self.payload_length, MessageID.unchoke.value)

        return message

    @classmethod
    def ntoh(cls, payload):
        raise NotImplementedError()


class Have(Message):
    payload_length = 4
    total_length = 5 + payload_length

    def __init__(self, piece_index):
        super(Have, self).__init__()
        self.piece_index = piece_index

    def hton(self):
        pack(">IBI", self.payload_length, MessageID.have.value, self.piece_index)

    @classmethod
    def ntoh(cls, payload):
        piece_index = unpack(">IBI", payload[:cls.payload_length])

        return Have(piece_index)


class Interested(Message):
    payload_length = 1

    def __init__(self):
        super(Interested, self).__init__()

    def hton(self):
        return pack(">IB", self.payload_length, MessageID.interested.value)

    @classmethod
    def ntoh(cls, payload):
        raise NotImplementedError()


class NotInterested(Message):
    payload_length = 1

    def __init__(self):
        super(NotInterested, self).__init__()

    def hton(self):
        message = pack(">IB", self.payload_length, MessageID.not_interested.value)
        return message

    @classmethod
    def ntoh(cls, payload):
        raise NotImplementedError()


# noinspection PyBroadException
class BitField(Message):
    payload_length = -1
    total_length = -1

    def __init__(self, bitfield):  # bitfield is a bitstring.BitArray
        super(BitField, self).__init__()

        self.bitfield = bitfield
        self.bitfield_as_bytes = bytes(bitfield)
        self.bitfield_length = len(self.bitfield_as_bytes)
        self.payload_length = 1 + self.bitfield_length
        self.total_length = 4 + self.payload_length

    def hton(self):
        return pack(">IB{}s".format(self.bitfield_length),
                    self.payload_length,
                    MessageID.bitfield.value,
                    self.bitfield_as_bytes)

    @classmethod
    def ntoh(cls, payload):
        bitfield = []
        for bit in bin(int.from_bytes(payload, "big")):
            bitfield.append(bit)

        try:
            bitfield.pop(0)
            bitfield.pop(0)
        except:  # bitfield was empty ("dummy bitfield")
            return BitField(bitfield)
        for index, elem in enumerate(bitfield):
            bitfield[index] = int(bitfield[index])
        while config.torrent.num_pieces - len(bitfield) != 0:
            try:
                bitfield.pop()
            except:
                return bitfield

        return BitField(bitfield)


class Request(Message):
    payload_length = 13
    total_length = 4 + payload_length

    def __init__(self, piece_index, block_offset, block_length):
        super(Request, self).__init__()

        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def hton(self):
        return pack(">IBIII",
                    self.payload_length,
                    MessageID.request.value,
                    self.piece_index,
                    self.block_offset,
                    self.block_length)

    @classmethod
    def ntoh(cls, payload):
        piece_index, block_offset, block_length = unpack(">III", payload[:len(payload)])

        return Request(piece_index, block_offset, block_length)


class PieceMsg(Message):
    payload_length = 9
    total_length = 4

    def __init__(self, block_length, piece_index, block_offset, block):
        super(PieceMsg, self).__init__()

        self.block_length = block_length
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block = block
        self.payload_length += block_length
        self.total_length += self.payload_length

    def hton(self):
        return pack(">IBII{}s".format(self.block_length),
                    self.payload_length,
                    MessageID.piece.value,
                    self.piece_index,
                    self.block_offset,
                    self.block)

    @classmethod
    def ntoh(cls, payload):
        piece_index, block_offset, block = unpack(">II{}s".format(len(payload) - 8), payload[:len(payload)])
        logging.debug('Recieved BLOCK: piece#{} block offset:{} block_length: {}'.format(piece_index, block_offset,
                                                                                         len(block)))
        block_length = len(block)

        return PieceMsg(block_length, piece_index, block_offset, block)


def recv_n_bytes(sock, n):
    res = 0
    buf = b''

    try:
        sock.send(b'')
    except IOError:
        peer = config.client.find_peer_by_socket(sock)
        peer.alive = False
        logging.error("Peer disconnected ip: {} port: {}".format(peer.ip, peer.port))
        return

    while res < n:
        r_len = 0
        try:
            r_data = sock.recv(n - res)
            r_len = len(r_data)

            res += r_len
            buf += r_data

        except BlockingIOError:
            continue
        if r_len == 0:
            return buf

    return buf


def recv_message(sock):
    # Return a tuple of: message_len, msg_id, payload

    buf = recv_n_bytes(sock, 4)
    message_len = unpack(">I", buf)[0]

    if message_len == 0:
        # keep alive
        return 0, 0, None
    else:
        buf = recv_n_bytes(sock, 1)
        msg_id = ord(unpack("c", buf)[0])
        payload = recv_n_bytes(sock, message_len - 1)
        return message_len, msg_id, payload


class MessageID(Enum):
    choke = 0
    unchoke = 1
    interested = 2
    not_interested = 3
    have = 4
    bitfield = 5
    request = 6
    piece = 7
    cancel = 8
    port = 9

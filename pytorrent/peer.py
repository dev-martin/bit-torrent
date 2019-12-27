import logging
import math
from time import sleep, time
import threading
from struct import unpack

from select import select
from threading import Thread
from time import sleep
from socket import socket, AF_INET, SOCK_STREAM

# noinspection PyBroadException
import config
from message import Handshake, Have, Choke, Interested, UnChoke, NotInterested, MessageID, Request, PieceMsg
from piece import PiecesManager

from message import recv_n_bytes, recv_message


class Peer(object):
    def __init__(self, peer_ip, peer_port):
        self.ip = peer_ip
        self.port = peer_port
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.peer_id = ''
        self.from_tracker_response = True  # attribute to be able to tell whether it is a peer from the tracker's list or one from outside
        self.handshaked = False
        self.am_choked = True
        self.am_interested = False
        self.peer_choked = True
        self.peer_interested = False
        self.bitfield = [0] * config.torrent.num_pieces
        self.piece_req = 0
        self.alive = True
        self.read_buffer = b''
        self.lock = threading.Lock()

    def handle_request(self):
        # do not use
        request = recv_n_bytes(self.sock, 12)

        requested_index = int.from_bytes(request[:4], "big")
        requested_begin = int.from_bytes(request[4:8], "big")
        requested_len = int.from_bytes(request[8:12], "big")

        # TODO: Return the index, begin, len.
        return 0

    def handle_have(self, payload):
        have = Have.ntoh(payload)
        return have.piece_index

    def send_handshake(self, handshake):
        with self.lock:
            self.sock.send(handshake)

    def recv_handshake(self):
        # receive info_hash
        with self.lock:
            payload = recv_n_bytes(self.sock, Handshake.payload_length)
            handshake = Handshake.ntoh(payload)

            # check info_hash
            with config.client.lock and config.torrent.lock:
                if handshake.info_hash != config.torrent.info_hash:
                    self.sock.close()
                    config.client.peers.pop(self)
                    logging.info(
                        "ERROR:Handshake received: IP: {} Port: {} Peer ID: {} With wrong Info Hash -- peer removed".format(self.ip, self.port, handshake.peer_id))
                    return -1
                # set peer id
                else:
                    self.peer_id = handshake.peer_id
                    logging.info("Handshake received: IP: {} Port: {} Peer ID: {} Info Hash: {}".format(
                        self.ip, self.port,
                        handshake.peer_id,
                        handshake.info_hash))
                    return 1

    def set_socket(self, sock):
        with self.lock:
            self.sock = sock

    def send_choke(self):  # sends whatever choking status we have with peer
        with self.lock:
            message = Choke() if self.peer_choked else UnChoke()
            self.sock.send(message.hton())

    def send_interest(self):
        with self.lock:
            message = Interested() if self.peer_interested else NotInterested()
            self.sock.send(message.hton())

    @staticmethod
    def generate_bitfield(payload):
        bitfield = []
        for b in payload:
            bits = list("{0:b}".format(b))
            bitfield.append(bits)

        bitfield = [y for x in bitfield for y in x]
        del (bitfield[config.torrent.num_pieces:])  # remove extra bits
        logging.info(bitfield)
        return bitfield

    def set_bitfield(self, bitfield):
        self.bitfield = bitfield

    def request_block(self, index, begin, length):
        request = Request(index, begin, length)
        with self.lock:
            self.sock.send(request.hton())

    def handle_bitfield_msg(self, peer, payload):
        with self.lock:
            bitfield = self.generate_bitfield(payload)

            peer.set_bitfield(bitfield)

            # todo - update peer.am_interested if peer has pieces we don't have
            with config.piece_manager.lock:
                for i in range(len(bitfield)):

                    if bitfield[i] == 0 and config.piece_manager.bitfield[i] == 1:
                        self.am_interested = 1
                        break

    def handle_interested_msg(self):
        with self.lock:
            self.peer_interested = True

    def handle_not_interested_msg(self):
        with self.lock:
            self.peer_interested = False

    def handle_choke_msg(self):
        with self.lock:
            self.am_choked = True

    def handle_unchoke_msg(self):
        with self.lock:
            self.am_choked = False

    def handle_piece_msg(self, payload):
        block_msg = PieceMsg.ntoh(payload)

        # update piece i with block just received
        with config.piece_manager.lock:
            config.piece_manager.insert_block_data_into_piece(block_msg.piece_index, block_msg.block_offset,
                                                              block_msg.block)
            logging.info("Received block for piece #{}".format(block_msg.piece_index))

            # piece corresponding to the block just received
            piece = config.piece_manager.pieces[block_msg.piece_index]

            # size of any piece but last one
            with config.torrent.lock:
                regular_piece_len = config.torrent.piece_len
                last_piece_len = config.torrent.length % config.torrent.piece_len

                # know if we are handling last piece
                if block_msg.piece_index == config.torrent.num_pieces - 1:
                    last_piece = True
                else:
                    last_piece = False

            # know how much data of piece we have in memory
            block_data = b''
            for block in piece.blocks:
                block_data += block['data']

            # handling last block in last piece(irregular size)
            if last_piece is True:
                logging.info("Handling last piece (#{})".format(piece.bitfield_index))
                # this means its last block
                # if piece correct --> write to disk and update bitfield/ else --> remove all data from piece and ask again
                # todo: uncomment below if(since im getting file from the seeder i just didnt want to check)
                # if config.piece_manager.verify_piece_against_piece_hash(piece.bitfield_index) is True:
                config.piece_manager.write_piece_to_disk(piece.bitfield_index)
                config.piece_manager.update_bitfield_have_piece(piece.bitfield_index)
                logging.info("Wrote last piece (#{}) to disk, we have the whole file!!\n>Current Bitfield\n {}".format(
                    piece.bitfield_index, config.piece_manager.bitfield))
                # todo: send Have to all Peers.
                # else:
                #     config.piece_manager.erase_piece(piece.bitfield_index)
                #     logging.info("Last piece (#{}) was wrong, sorry about that (erasing erroneous data...)!!\n>Current Bitfield\n {}".format(
                #         piece.bitfield_index,config.piece_manager.bitfield))

            # handling last block in any other piece
            else:
                if len(block_data) == regular_piece_len:  # this means its last block
                    # if piece correct --> write to disk and update bitfield/ else --> remove all data from piece and ask again
                    # todo: uncomment below if(since im getting file from the seeder i just didnt want to check)
                    # if config.piece_manager.verify_piece_against_piece_hash(piece.bitfield_index) is True:
                    config.piece_manager.write_piece_to_disk(piece.bitfield_index)
                    config.piece_manager.update_bitfield_have_piece(piece.bitfield_index)
                    logging.info("Wrote piece #{} to disk\n>Current Bitfield\n {}".format(
                        piece.bitfield_index, config.piece_manager.bitfield))
                    # else:
                    #     config.piece_manager.erase_piece(piece.bitfield_index)
                    #     logging.info("Piece #{} was wrong, sorry about that (erasing erroneous data...)!!\n>Current Bitfield\n {}".format(
                    #         piece.bitfield_index,config.piece_manager.bitfield))


class PeerHandler(Thread):

    def __init__(self):
        super().__init__()

    def run(self):

        while True:

            read = [peer.sock for peer in config.client.peers]
            read_list, _, _ = select(read, [], [], 1)

            for sock in read_list:
                peer = config.client.find_peer_by_socket(sock)
                logging.info("Handling receive from: IP: {} Port: {}".format(peer.ip, peer.port))

                try:
                    message_len, msg_id, payload = recv_message(sock)

                    if msg_id == 0:
                        logging.info("handle keep_alive message  from: IP: {} Port: {}".format(peer.ip, peer.port))
                    if msg_id == MessageID.choke.value:
                        logging.info("handle_choke_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        peer.handle_choke_msg()
                    elif msg_id == MessageID.unchoke.value:
                        logging.info("handle_unchoke_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        peer.handle_unchoke_msg()
                    elif msg_id == MessageID.interested.value:
                        logging.info("handle_interested_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        peer.handle_interested_msg()
                    elif msg_id == MessageID.not_interested.value:
                        logging.info("handle_interested_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        peer.handle_not_interested_msg()
                    elif msg_id == MessageID.have.value:
                        logging.info("handle_not_interested_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        # process_have_msg(payload, sock)
                        # TODO Update peer's bitfield upon receiving a Have.
                    elif msg_id == MessageID.bitfield.value:
                        logging.info("handle_bitfield_msg from: IP: {} Port: {}".format(peer.ip, peer.port))
                        peer.handle_bitfield_msg(peer, payload)
                    elif msg_id == MessageID.request.value:
                        logging.info("handle_request_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        # process_request_msg(payload, sock)
                        # TODO Respond to a Request if the Peer is unchoked.
                    elif msg_id == MessageID.piece.value:
                        logging.info("handle_piece_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        peer.handle_piece_msg(payload)
                    elif msg_id == MessageID.cancel.value:
                        logging.info("handle_cancel_msg  from: IP: {} Port: {}".format(peer.ip, peer.port))
                        # process_cancel_msg(payload, sock)
                        # TODO Note that a Peer Cancelled a Request.
                    else:
                        logging.info(
                            "undefined message ID {} from {} on {} Message Len: {}".format(msg_id, peer.ip, peer.port,
                                                                                           message_len))
                        exit()
                except BlockingIOError:
                    pass


class KeepAlive(Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        logging.debug(" Keep Alive Thread Started")
        while True:
            with config.client.lock:
                for peer in config.client.peers:
                    with peer.lock:
                        if peer is None:
                            continue
                        elif peer.handshaked:
                            try:
                                peer.sock.send(b'')
                                logging.info(" Keep Alive sent to IP: {} Port: {}:".format(peer.ip, peer.port))
                            except IOError:
                                peer.alive = False
                                logging.error("Peer disconnected ip: {} port: {}".format(peer.ip, peer.port))
            # TODO Change the per-Peer keep-alive timer to a 2-minute alarm that gets reset every time a
            #  message is sent from/to the Peer.
            sleep(150)


class Download(Thread):
    def __init__(self):
        super().__init__()

    # TODO Theory.org specification says, "Clients may chose to download pieces in random order."
    #  This is a nice-to-have feature. The next step would be downloading rarest-first.

    def run(self):
        while True:
            sleep(10)
            # with config.piece_manager.lock:
            for piece in config.piece_manager.pieces:
                if piece is None:
                    continue
                with piece.lock:
                    index = piece.bitfield_index

                    if index is None:
                        continue

                    with config.client.lock:
                        if len(config.client.peers) == 0:
                            continue

                    peers = config.piece_manager.get_peers_with_piece(index)

                    if len(peers) == 0:
                        logging.debug("No peers with piece #{}".format(index))
                        continue
                    else:
                        for peer in peers:

                            for block in piece.blocks:

                                if not block['downloaded'] and block['time_requested'] + 20 < time():
                                    block['requested'] = False

                                if not block['downloaded'] and not block['requested']:
                                    # request block from peer
                                    if index == 85:
                                        pass

                                    logging.info(
                                        "Requesting block: Index: {} Begin: {} Length: {} from peer IP: {} Port: {}".format(
                                            index, block['begin_offset'], block['size'], peer.ip, peer.port))

                                    peer.request_block(index, block['begin_offset'], block['size'])

                                    block['time_requested'] = time()
                                    block['requested'] = True

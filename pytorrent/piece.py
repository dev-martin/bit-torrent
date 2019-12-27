import logging
from threading import Thread
import math
import os
import config
from message import PieceMsg
from hashlib import sha1
import threading


class PiecesManager(object):

    def __init__(self):

        # bitfield of pieces we currently have; updated live
        self.bitfield = self.init_bitfield()

        # list of pieces (each piece is empty at initialization)
        self.pieces = self.generate_pieces()

        # number of pieces we currently have; updated live
        # TODO Update this upon acquisition of each Piece.
        self.complete_pieces = 0

        self.lock = threading.Lock()
    # def interested_in_peer(self, peer):
    #
    #     # should be used when determining whether we're initially interested in this peer
    #     for i in range(peer.bitfield.length):
    #         if self.bitfield[i] == 0 and peer.bitfield[i] == 1:
    #             return True
    #
    #     return False

    @staticmethod
    def init_bitfield():
        logging.debug("initialized PieceManager bitfield")
        with config.torrent.lock:
            bitfield = [0] * config.torrent.num_pieces
        return bitfield

    @staticmethod
    def generate_pieces():
        logging.debug("generate pieces bitfield")
        pieces = list()

        with config.torrent.lock:
            for i in range(config.torrent.num_pieces):
                pieces.append(Piece(i))

            # the last piece is special; give him different block sizes
            last_piece = pieces[config.torrent.num_pieces - 1]
            last_block = last_piece.blocks[last_piece.num_blocks - 1]
            remainder = config.torrent.length % config.torrent.piece_len
            last_block['size'] = remainder % last_block['size']

        return pieces

    def insert_block_data_into_piece(self, index, begin, block):
        # index: which piece to add bytes to?
        # begin: offset within piece
        # block: bytes of data
        # to be called upon reception of a "piece" Message
        with self.pieces[index].lock:
            logging.debug("insert block into piece {} at offset {}".format(index, begin))
            piece = self.pieces[index]
            blocks = piece.blocks
            with config.torrent.lock:
                block_list_index = int(math.floor(begin / config.torrent.block_size))
            blocks[block_list_index]['data'] = block
            blocks[block_list_index]['downloaded'] = True

    def verify_piece_against_piece_hash(self, index):
        # index: which piece to verify?
        # to be called after all blocks of a piece are received
        # to be called before writing piece to disk
        # todo: hashes are different because one is in binary data and the othre is in hexdigest

        # from info dictionary
        with config.torrent.lock:
            piece_hash = config.torrent.piece_hash_list[index].hex()

        # what we have
        with self.pieces[index].lock:
            piece = self.pieces[index]
            hash_over_blocks = piece.compute_piece_hash_over_current_blocks()

            if hash_over_blocks == piece_hash:
                logging.debug("piece {} hash over blocks is verified correct".format(index))
                return True
            else:
                return False

    def update_bitfield_have_piece(self, index):
        # index: which piece to say "I have"
        # To be called after correctly verifying a received Piece
        # for internal keeping-track

        self.bitfield[index] = 1

    def write_piece_to_disk(self, index):
        # index: which piece to write to disk?
        #  wipe piece bytes from memory after finished writing to disk; no longer needed in memory
        logging.info("Writing piece #{} to disk...".format(index))

        # TODO Devise an algorithm for writing pieces to their respective paths in multi-file mode.

        with self.pieces[index].lock and config.torrent.lock:
            position = config.torrent.piece_len * index
            data = b''
            for block in self.pieces[index].blocks:
                data += block['data']

            if not os.path.isdir("../Downloads"):
                os.mkdir("../Downloads")

            download = open("../Downloads/"+config.torrent.filename, 'ab')  # we want to append each piece

            download.seek(position)
            download.write(data)

            # clear piece from RAM
            self.pieces[index].generate_blocks()

    def erase_piece(self,index):
        # remove data from erroneous piece
        with self.pieces[index].lock:
            self.pieces[index].blocks = Piece.generate_blocks()
            self.bitfield[index] = [0]

    @staticmethod
    def pieces_complete():
        return False

    @staticmethod
    def get_peers_with_piece(index):
        peers = list()
        with config.client.lock:
            for peer in config.client.peers:
                with peer.lock:
                    if peer.handshaked and not peer.am_choked and peer.alive and peer.bitfield[index] == '1':
                        peers.append(peer)
        return peers


class Piece(object):
    def __init__(self, bitfield_index):
        self.bitfield_index = bitfield_index
        self.num_blocks = int(math.ceil(float(config.torrent.piece_len) / config.torrent.block_size))
        self.blocks = self.generate_blocks()
        self.lock = threading.Lock()

    def generate_blocks(self):
        # called at initialization of a Piece object
        blocks = list()

        for i in range(self.num_blocks):
            block = {'data': b'',
                     'size': config.torrent.block_size,
                     'time_requested': -1,
                     'downloaded': False,  # TODO Set 'downloaded' flag to True upon Piece acquisition.
                     'begin_offset': config.torrent.block_size * i,
                     'requested': False}
            blocks.append(block)

        return blocks

    def compute_piece_hash_over_current_blocks(self):
        # should be called when all blocks of this piece have been received
        current_blocks = b''
        for block in self.blocks:
            current_blocks += block['data']
        piece_hash = sha1(current_blocks).hexdigest()
        return piece_hash



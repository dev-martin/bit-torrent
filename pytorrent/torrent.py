import logging

from bcoding import bencode, bdecode
from hashlib import sha1
from math import ceil
import threading


class Torrent(object):
    def __init__(self):
        self.meta = {}
        self.piece_len: int = 0
        self.block_size: int = 0
        self.pieces: str = ''
        self.num_pieces: int = 0
        self.private: int = 0
        self.filename: str = ''
        self.dirname: str = ''
        self.length: int = 0
        self.md5sum: str = ''
        self.piece_hash_list = list()
        self.files = []
        self.tracker: str = ''
        self.info_hash: str = ''
        self.lock = threading.Lock()

    def from_file(self, file_path):
        with open(file_path, 'rb') as file:
            self.meta = file.read()
            keys = bdecode(self.meta)
            file.close()

        if 'length' in keys['info']:
            self.filename = keys['info']['name']
            self.length = keys['info']['length']
        elif 'files' in keys['info']:
            self.dirname = keys['info']['name']
            self.files = keys['info']['files']

            for file in keys['info']['files']:
                self.length += file['length']
        else:
            logging.info("Error: Torrent {} is neither single-file nor multiple-file mode".format(keys['info']['name']))
            exit(-1)

        self.tracker = keys['announce']
        self.pieces = keys['info']['pieces']
        self.info_hash = self.generate_info_hash(keys['info'])
        self.piece_len = keys['info']['piece length']
        self.block_size = min(16384, self.piece_len / 2)
        self.num_pieces = ceil(self.length / self.piece_len)
        self.piece_hash_list = [self.pieces[i:i + 20] for i in range(0, 20 * (self.num_pieces + 1), 20)]

        return self

    @staticmethod
    def generate_info_hash(info):
        info_encoded = bencode(info)
        info_hash = sha1(info_encoded).hexdigest()
        logging.debug("Serving info_hash {}".format(info_hash))
        return info_hash

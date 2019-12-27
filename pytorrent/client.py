import logging
from threading import Thread
import config
from peer import Peer
from hashlib import sha1
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import threading

# noinspection PyBroadException
from message import Handshake


class Client:
    # Constructor
    def __init__(self, port, ip_addr):
        self.port = port
        self.ip_addr = ip_addr
        self.uploaded = 0  # TODO Increment this counter upon sending a Piece.
        self.downloaded = 0  # TODO Increment this counter upon receiving a Piece.
        self.left = 0  # TODO Decrement this counter upon receiving a Piece.
        self.id = ''
        self.threads = list()
        self.peers = list()
        self.listen = socket(AF_INET, SOCK_STREAM)
        self.listen.setblocking(False)
        self.listen.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.listen.bind((ip_addr, port))
        self.listen.listen(32)
        self.lock = threading.Lock()

    @property
    def id(self):
        return self._id

    @property
    def downloaded(self):
        return self._downloaded

    @property
    def uploaded(self):
        return self._uploaded

    @property
    def left(self):
        return self._left

    @property
    def port(self):
        return self._port

    @property
    def ip_addr(self):
        return self._ip_addr

    @id.setter
    def id(self, value):
        seed = str(value)
        self._id = sha1(seed.encode('utf-8')).digest()

    @downloaded.setter
    def downloaded(self, value):
        self._downloaded = value

    @left.setter
    def left(self, value):
        self._left = value

    @uploaded.setter
    def uploaded(self, value):
        self._uploaded = value

    @ip_addr.setter
    def ip_addr(self, value):
        self._ip_addr = value

    @port.setter
    def port(self, value):
        self._port = value

    def find_peer(self, ip_addr, port):
        with self.lock:
            if len(self.peers) == 0:
                return False, None

            peer_found = False
            found_peer = Peer(0, 0)
            for peer in self.peers:
                if peer.ip == ip_addr and peer.port == port:
                    peer_found = True
                    found_peer = peer
                    break
            return peer_found, found_peer

    def find_peer_by_socket(self, sock):
        with self.lock:
            if len(self.peers) == 0:
                return None

            for peer in self.peers:
                if peer.sock == sock:
                    return peer

            return None


class Listener(Thread):

    def __init__(self):
        super().__init__()

    def run(self):
        # TODO Listen, accept, and handshake with new Peers, then add them to peer list.
        logging.info("Listener started.")
        while True:
            new_sock = None
            new_addr = (' ', 0)

            while new_sock is None:
                try:
                    new_sock, new_addr = config.client.listen.accept()
                    logging.info("Accepted new connection to IP: {} Port: {}".format(new_addr[0], new_addr[1]))
                except BlockingIOError as e:
                    continue

            # see if this peer is in out peer list , if he is not, we have to add him if we don't exceed the peer limit
            peer = config.client.find_peer_by_socket(new_sock)
            if peer is None and len(config.client.peers) < 10:
                new_peer = Peer(new_addr[0], new_addr[1])
                new_peer.set_socket(new_sock)
                new_peer.from_tracker_response = False
                with config.client.lock:
                    config.client.peers.append(new_peer)
                assert new_peer.recv_handshake() == 1

                handshake = Handshake(bytes.fromhex(config.torrent.info_hash))
                new_peer.send_handshake(handshake.hton())

                new_peer.handshaked = True





import http.client
import http.client
import logging
from socket import socket, inet_ntoa, AF_INET, SOCK_STREAM
from threading import Thread
from time import sleep
from urllib import parse

from bcoding import bdecode

import config
import threading
from message import Handshake
from peer import Peer


class Tracker:
    def __init__(self):
        self.interval = 0
        self.tracker_id = ''
        self.complete = 0
        self.incomplete = 0
        self.lock = threading.Lock()


class Announce(Thread):

    def __init__(self):
        super().__init__()

    def run(self):
        while True:

            # TODO Disconnect with (and drop) current Peers, so we can (re)connect to each Peer in the new peer list.

            with config.client.lock and config.torrent.lock:
                request = {
                    'info_hash': bytes.fromhex(config.torrent.info_hash),
                    'peer_id': config.client.id,
                    'port': config.client.port,
                    'uploaded': config.client.uploaded,
                    'downloaded': config.client.downloaded,
                    'left': config.client.left,
                    'compact': 1
                }

            query = '/announce?' + parse.urlencode(request, encoding="utf-8")
            with config.torrent.lock:
                announce_url = config.torrent.tracker.replace("/announce", "").replace("http://", "")

            connection = http.client.HTTPConnection(announce_url)
            connection.request("GET", query)
            logging.info("Tracker request sent.")

            with connection.getresponse() as response:
                if not response.status == 200:
                    raise ConnectionError('Unable to connect to tracker')
                meta = response.read()

            logging.info("Tracker response received.")
            response = bdecode(meta)

            # set announce wait to time amound specified by the tracker
            with config.tracker.lock:
                config.tracker.interval = response['interval']

            peers_from_tracker = []
            if request['compact'] == 1:
                # transform peers in response to a dictionary
                byte_list = [response['peers'][i:i + 6] for i in range(0, len(response['peers']), 6)]

                for byte in byte_list:
                    ip = inet_ntoa(byte[:4])
                    port = int.from_bytes(byte[4:6], "big")
                    peer_exists, peer_found = config.client.find_peer(ip, port)
                    if not peer_exists:
                        peers_from_tracker.append(Peer(ip, port))
            else:
                # transform dictionary response to list of Peer objects
                # Non-compact mode is not tested because 417 Tracker only sends Compact peers (binary model).
                for peer in response['peers']:
                    new_peer = Peer((peer['ip'], peer['port']))
                    new_peer.peer_id = peer['peer id']
                    peers_from_tracker.append(new_peer)

            logging.info("Peers list from tracker: {}".format(peers_from_tracker))

            # peer = Peer("128.8.126.63", 51413)

            for peer in peers_from_tracker:
                if not peer.handshaked and peer.ip != "127.0.0.1":  # and peer.ip == "128.8.126.63":
                    
                    peer.sock = socket(AF_INET, SOCK_STREAM)

                    peer.sock.settimeout(0.5)
                    connect_status = peer.sock.connect_ex((peer.ip, peer.port))
                    if connect_status != 0:
                        logging.debug("Could not connect to Peer: IP: {} Port: {}".format(peer.ip, peer.port))
                        # timed out
                        continue
                    peer.sock.settimeout(None)

                    peer.sock.setblocking(False)
                    
                    handshake = Handshake(bytes.fromhex(config.torrent.info_hash))
                    peer.send_handshake(handshake.hton())
                    logging.info(
                        "Handshake sent: Peer IP: {} Port: {} Handshake: {}".format(peer.ip, peer.port, handshake))

                    status = peer.recv_handshake()
                    if status == 1:
                        logging.info("Handshake complete: Peer IP: {} Port: {}".format(peer.ip, peer.port))
                        peer.handshaked = True
                        peer.from_tracker_response = False
                        with config.client.lock:
                            config.client.peers.append(peer)
                    else:
                        logging.info("Handshake failed with Peer IP: {} Port: {}".format(peer.ip, peer.port))

            sleep(config.tracker.interval)

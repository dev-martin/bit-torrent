import logging
import math
import sys
from os import system
from datetime import time
from select import select
from time import sleep

import config
from message import Request
from peer import PeerHandler, KeepAlive, Download
from client import Listener
from tracker import Announce

if __name__ == "__main__":

    prompts = 1

    if len(sys.argv) == 3:
        if sys.argv[2] == "DEBUG":
            logging.basicConfig(level=logging.DEBUG)
            prompts = 0

    logging.debug("Test")

    config.init_globals(5555)
    # set up client id
    config.client.id = time()
    # read and parse torrent
    config.torrent.from_file(sys.argv[1])

    config.client.left = config.torrent.length

    config.init_piece_manager()

    tracker_thread = Announce()
    config.client.threads.append(tracker_thread)
    tracker_thread.start()

    peer_handler_thread = PeerHandler()
    config.client.threads.append(peer_handler_thread)
    peer_handler_thread.start()

    listener_thread = Listener()
    config.client.threads.append(listener_thread)
    listener_thread.start()

    keep_alive_thread = KeepAlive()
    config.client.threads.append(keep_alive_thread)
    keep_alive_thread.start()

    request_pieces_thread = Download()
    config.client.threads.append(request_pieces_thread)
    request_pieces_thread.start()

    if prompts == 1:
        bar_width = 100
        system('clear')
        ## debuggin purpose
        print("\t\t\t\t\t*** Welcome to BitTorrentPy ***")
        print("\t\t\tRobert Nash, Martin Iglesia, Spencer Michalski, Mike O'Brien")
        print("\n")

        sys.stdout.write("Downloading: [{}]".format(" " * bar_width))
        sys.stdout.flush()
        sys.stdout.write("\b" * (bar_width + 1))  # return to start of line, after '['

        total = 0
        while config.piece_manager.bitfield.count(0) != 0:
            sleep(0.1)
            update = math.floor((config.piece_manager.bitfield.count(1) / len(config.piece_manager.bitfield)) * 100)
            sys.stdout.write("=" * (update - total))
            sys.stdout.flush()
            total += (update - total)

        print("]\n")
        print("File complete.")
        print("File saved to downloads/{}".format(config.torrent.filename))

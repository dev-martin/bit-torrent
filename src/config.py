from client import Client
from torrent import Torrent
from tracker import Tracker
from piece import PiecesManager

global client
global torrent
global tracker
global piece_manager


def init_globals(port_to_bind):
    global client
    global torrent
    global tracker
    global piece_manager

    client = Client(port_to_bind, "0.0.0.0")
    torrent = Torrent()
    tracker = Tracker()


def init_piece_manager():
    global piece_manager
    piece_manager = PiecesManager()




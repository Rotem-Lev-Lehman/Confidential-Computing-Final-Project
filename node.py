# confidential_computing

from datetime import time
import json
import socket
import threading
import queue

NODES = 4

class Node:
    def __init__(self, node_id, config):
        self.node_id = node_id
        self.peers = {nid: addr for nid, addr in config.items() if nid != node_id}
        self.inbox = queue.Queue()
        self.host = config[node_id]['host']
        self.port = config[node_id]['port']
        self.connections = {}  # sockets to peers - connections[peer_id] -> socket
        ...

    def start_listener(self):
        # socket.socket + bind + listen, בתוך thread נפרד

        # when using AF_INET, addresses must be formatted as a tuple containing a string and an integer: ('IP_ADDRESS', PORT)
        # for IPv6 addresses use socket.AF_INET6 check internet for more details 
        # socket.SOCK_STREAM force the socket to use TCP protocol, for UDP use socket.SOCK_DGRAM
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # SOL_SOCKET go to socker setting layer, SO_REUSEADDR the setting i want to change meaning to reuse address or port, 1 means true.
        s.bind((self.host, self.port)) 
        s.listen(NODES - 1)  # NODES - 1 connections for each node.
        # לכל חיבור נכנס -> thread חדש שקורא הודעות ושם ב-inbox

        def accept_loop():
            while True:
                conn, _ = s.accept()          # returns (connection_socket, *client*_address) & it blocks until new connection is established 
                t = threading.Thread(target=self._handle_connection, args=(conn,), daemon=True) # deamon=True means that the thread will exit when the main program exits, even if the thread is still running.
                t.start()

        threading.Thread(target=accept_loop, daemon=True).start()


    def _handle_connection(self, conn):
        f = conn.makefile('r')   # נותן לך readline() נוח על גבי הסוקט
        while True:
            line = f.readline()
            if not line:
                break            # הצד השני סגר את החיבור
            message = json.loads(line)
            #TODO: enter message with phase 
            self.inbox.put(message)


    def connect_to_peer(self, peer_id, retries=10, delay=0.5):
        # יוזם חיבור TCP ל-peer, שומר את הסוקט לשימוש חוזר לשליחה
        peer_addr = self.peers[peer_id]
        for _ in range(retries):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((peer_addr['host'], peer_addr['port']))
                self.connections[peer_id] = s
                return
            except ConnectionRefusedError:
                time.sleep(delay)
            raise ConnectionError(f"Could not connect to peer {peer_id}")
        # solve race condition at the beginning of the program, when all nodes try to connect to each other at the same time, some connections may be
        # refused because the peer has not started listening yet. To solve this, we can implement a retry mechanism with a delay between retries. 


    def send(self, peer_id, message: dict):
        # ממיר ל-JSON, מוסיף \n, שולח בסוקט הפתוח ל-peer_id
        peer_s = self.connections.get(peer_id) # a socket
        if peer_s is None:
            raise ValueError(f"No connection to peer {peer_id}")
        
        peer_s.sendall((json.dumps(message) + "\n").encode('utf-8')) # encode & '\n' matched to readline() in _handle_connection


"""
    def broadcast(self, message: dict):
        message["from"] = self.node_id
        # send לכל שלושת השאר
        for peer_id in self.peers:
            node.send(peer_id, {"payload": shares[peer_id]})   # payload שונה לכל peer!
"""

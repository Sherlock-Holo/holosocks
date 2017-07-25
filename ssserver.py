#!/usr/bin/env python3

import argparse
import json
import logging
import select
import socket
import struct
from socketserver import StreamRequestHandler, ThreadingTCPServer

from encrypt import aes_cfb


SOCSK_VERSION = 5    # use socks5
SOCKS_AUTHENTICATION = 0    # no Authentication
SOCKS_MODE = 1    # mode: connection


class Socks5Server(StreamRequestHandler):
    def encrypt(self, data):    # encrypt data
        return aes_256_cfb.encrypt(data)

    def decrypt(self, data):    # decrypt data
        return aes_256_cfb.decrypt(data)

    def tcp_relay(self, sock, remote):    # relay data
        try:
            while True:
                r, w, e = select.select([sock, remote], [], [])
                if sock in r:
                    if remote.send(self.decrypt(sock.recv(4096))) <= 0:
                        break

                if remote in r:
                    if sock.send(self.encrypt(remote.recv(4080))) <= 0:
                        break

        finally:
            sock.close()
            remote.close()

    def handle(self):
        try:
            sock = self.connection

            addr_type = self.decrypt(self.rfile.read(1))
            if addr_type == 1:
                addr_ip = self.decrypt(self.rfile.read(4))    # addr ip (4 bytes)
                addr = socket.inet_ntoa(addr_ip)    # get target addr

            elif addr_type == 3:
                addr_len = self.decrypt(self.rfile.read(1))    # addr len (1 byte)
                addr = self.decrypt(self.rfile.read(ord(addr_len)))  # domain name

            _port = self.decrypt(self.rfile.read(2))    # get port (2 bytes)
            port = struct.unpack('>H', _port)

            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote.connect((addr, port))    # connect to target
            self.tcp_relay(sock, remote)

        except socket.error as e:
            logging.warn(e)


def main():
    logging.basicConfig(level=logging.DEBUG,
                        format='{asctime} {levelname} {message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        style='{')

    parser = argparse.ArgumentParser(description='shadowsocks local')
    parser.add_argument('-c', '--config', help='config file')
    args = parser.parse_args()
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    SERVER = config['server']
    SERVER_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    aes_256_cfb = aes_cfb(KEY)

    with ThreadingTCPServer((SERVER, SERVER_PORT), Socks5Server) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
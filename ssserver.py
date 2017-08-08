#!/usr/bin/env python3

import argparse
import gevent
import json
import logging
import struct
from gevent import socket
from gevent.server import StreamServer

from encrypt import aes_cfb

logging.basicConfig(level=logging.DEBUG,
                    format='{asctime} {levelname} {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    style='{')


class Socks5Server(StreamServer):
    def sock2remote(self, fr, to):
        try:
            while True:
                data = fr.recv(4096)
                if len(data) <= 0:
                    return None
                #data = self.de.decrypt(data)
                to.send(data)

        except socket.error:
            return None

    def remote2sock(self, fr, to):
        try:
            while True:
                data = fr.recv(4096)
                if len(data) <= 0:
                    return None
                #data = self.en.encrypt(data)
                to.send(data)

        except socket.error:
            return None

    def handle(self, sock, address):
        logging.info('socks connection from {}'.format(address))
        # create encrypt function
        iv = sock.recv(16)
        self.en = aes_cfb(KEY)
        self.en.new(iv)
        self.de = aes_cfb(KEY)
        self.de.new(iv)

        atyp = sock.recv(1)
        logging.info('atyp: {}'.format(atyp))
        addr_type = ord(atyp)
        logging.info('addr type: {}'.format(addr_type))

        if addr_type == 1:
            addr_ip = sock.recv(4)
            addr = socket.inet_ntoa(addr_ip)

        elif addr_type == 3:
            addr_len = sock.recv(1)
            logging.info('addr len: {}'.format(ord(addr_len)))
            addr = sock.recv(ord(addr_len))

        else:
            sock.close()
            logging.error('from {}, not support addr type({})'.format(address, addr_type))
            return None

        port = struct.unpack('>H', sock.recv(2))[0]

        logging.info('address: {}, port: {}'.format(addr, port))

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((addr, port))

        # start relay
        logging.info('start relay')
        sock2remote = gevent.spawn(self.sock2remote, sock, remote)
        remote2sock = gevent.spawn(self.remote2sock, remote, sock)
        gevent.joinall((sock2remote, remote2sock))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='shadowsocks server')
    parser.add_argument('-c', '--config', help='config file')
    args = parser.parse_args()
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    SERVER = config['server']
    SERVER_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    try:
        server = Socks5Server((SERVER, SERVER_PORT))
        server.serve_forever()

    except KeyboardInterrupt:
        server.close()

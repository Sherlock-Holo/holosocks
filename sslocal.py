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
                if to.send(self.en.encrypt(fr.recv(4096))) <= 0:
                    break

        except socket.error:
            pass

    def remote2sock(self, fr, to):
        try:
            while True:
                if to.send(self.de.decrypt(fr.recv(4096))) <= 0:
                    break

        except socket.error:
            pass

    def handle(self, sock, address):
        logging.info('socks connection from {}'.format(address))

        ask = sock.recv(3)    # connect to socks server
        logging.info(ask[0])
        if ask[0] == 5:    # check version
            if ask[-1] == 0:    # check Authentication info
                sock.send(b'\x05\x00')

            else:
                logging.error('Authentication error')
                sock.send(struct.pack('>BB', 0x05, 0xff))
                sock.close()
                return None
        else:
            logging.error('version error')
            sock.close()
            return None

        logging.info('Authentication successed')

        data = sock.recv(4)    # request format: VER CMD RSV ATYP (4 bytes)
        if not data[1] == 1:    # CMD not support
            addr_and_port = socket.inet_aton('0.0.0.0') + struct.pack('>H', 0)
            sock.send(b'\x05\x07\x00\x01' + addr_and_port)

        addr_type = data[3]    # get atyp (1 byte)
        logging.info('addr type: {}'.format(addr_type))
        data_to_send = struct.pack('>B', addr_type)

        if addr_type == 1:
            addr = socket.inet_ntoa(sock.recv(4))    # ipv4

        elif addr_type == 3:
            addr_len = sock.recv(1)
            data_to_send += addr_len
            addr = sock.recv(ord(addr_len))    # domain name

        else:
            addr_and_port = socket.inet_aton('0.0.0.0') + struct.pack('>H', 0)
            sock.send(b'\x05\x08\x00\x01' + addr_and_port)
            sock.close()
            return None

        data_to_send += addr

        _port = sock.recv(2)    # get target port
        port = struct.unpack('>H', _port)[0]
        logging.info('address: {}, port: {}'.format(addr, port))

        data_to_send += _port

        # create encrypt function
        self.en = aes_cfb(KEY)
        self.en.new()
        iv = self.en.iv
        self.de = aes_cfb(KEY)
        self.de.new(iv)

        # connect ssserver
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((SERVER, SERVER_PORT))
        logging.info('connected ssserver')
        remote.send(iv)    # send iv
        remote.send(self.en.encrypt(data_to_send))

        data = b'\x05\x00\x00\x01'
        data += socket.inet_aton('0.0.0.0') + struct.pack('>H', 0)
        sock.send(data)

        # start relay
        logging.info('start relay')
        sock2remote = gevent.spawn(self.sock2remote, sock, remote)
        remote2sock = gevent.spawn(self.remote2sock, remote, sock)
        gevent.joinall((sock2remote, remote2sock))


if __name__ == '__main__':
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

    try:
        server = Socks5Server(('127.0.0.2', PORT))
        server.serve_forever()

    except KeyboardInterrupt:
        server.close()

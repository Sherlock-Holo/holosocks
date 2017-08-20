#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import struct

from encrypt import aes_cfb

logging.basicConfig(level=logging.INFO,
                    format='{asctime} {levelname} {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    style='{')


class Remote(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = None
        self.Encrypt = None

    def data_received(self, data):
        self.server_transport.write(self.Encrypt.encrypt(data))


class Server(asyncio.Protocol):
    INIT, CONNECTING_TARGET, RELAY = range(3)

    def connection_made(self, transport):
        sslocal_info = transport.get_extra_info('peername')
        logging.debug('shadowsocks local {}'.format(sslocal_info))
        self.transport = transport
        self.state = self.INIT
        self.data_len = 0
        self.data_buf = b''
        self.Encrypt = None
        self.Decrypt = None

        # test
        self.addr_len = 0

    def data_received(self, data):
        if self.state == self.INIT:
            # recv iv
            self.data_buf += data
            self.data_len += len(data)
            if self.data_len < 16:
                return None

            elif self.data_len == 16:
                iv = self.data_buf
                self.Encrypt = aes_cfb(KEY, iv)
                self.Decrypt = aes_cfb(KEY, iv)
                return None

            elif self.data_len > 16:
                if not self.Encrypt:
                    iv = self.data_buf[:16]
                    logging.debug('iv: {}'.format(iv))
                    self.Encrypt = aes_cfb(KEY, iv)
                    self.Decrypt = aes_cfb(KEY, iv)

                if not self.addr_len:
                    _addr_len = struct.pack('>B', self.data_buf[16])
                    #logging.debug('target: {}'.format(self.data_buf))
                    self.addr_len = ord(self.Decrypt.decrypt(_addr_len))
                    logging.debug('addr len: {}'.format(self.addr_len))

                if self.data_len < 16 + 1 + self.addr_len + 2:
                    return None

                elif self.data_len == 16 + 1 + self.addr_len + 2:
                    plain_data = self.Decrypt.decrypt(self.data_buf)
                    addr = plain_data[17:17 + self.addr_len]
                    port = struct.unpack('>H', plain_data[-2:])[0]

                    # clear buffer and counter
                    self.data_len = 0
                    self.data_buf = b''

                elif self.data_len > 16 + 1 + self.addr_len + 2:
                    _len = 16 + 1 + self.addr_len + 2
                    plain_data = self.Decrypt.decrypt(self.data_buf[:_len])

                    # buffer the content which sends with target message
                    self.data_buf = self.data_buf[_len:]
                    self.data_len = len(self.data_buf)

                    addr = plain_data[17:17 + self.addr_len]
                    logging.debug('addr: {}'.format(addr))
                    logging.debug('port: {}'.format(plain_data[-2:]))
                    port = struct.unpack('>H', plain_data[-2:])[0]

            logging.debug('target: {}:{}'.format(addr, port))

            # connect to taeget
            self.target = asyncio.ensure_future(self.connect(addr, port))
            self.state = self.CONNECTING_TARGET

        elif self.state == self.CONNECTING_TARGET:
            self.data_buf += data
            if self.target.done():    # connected target
                # There are 2 cases:
                # Connected to target before call it, so data in buffer will
                # send to target and buffer will be empty. (else case)
                #
                # Buffer the data after connected to target, so it will send
                # data to target. (if case)
                if self.data_buf == b'':
                    self.state = self.RELAY
                else:
                    plain_data = self.Decrypt.decrypt(self.data_buf)
                    self.remote_transport.write(plain_data)
                    self.state = self.RELAY

                logging.debug('start relay')

        elif self.state == self.RELAY:
            self.remote_transport.write(self.Decrypt.decrypt(data))

    async def connect(self, addr, port):
        logging.debug('connecting target')
        loop = asyncio.get_event_loop()
        transport, remote = await loop.create_connection(Remote, addr, port)
        remote.server_transport = self.transport    # set target_transport
        remote.Encrypt = self.Encrypt
        self.remote_transport = transport    # set remote_transport
        logging.debug('target connected')
        if self.data_buf:
            self.remote_transport.write(self.Decrypt.decrypt(self.data_buf))
        self.data_buf = b''


if __name__ == '__main__':
    logging.info('start shadowsocks server')
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

    loop = asyncio.get_event_loop()
    _server = loop.create_server(Server, '0.0.0.0', SERVER_PORT)
    server = loop.run_until_complete(_server)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import struct

from encrypt import aes_cfb

logging.basicConfig(level=logging.DEBUG,
                    format='{asctime} {levelname} {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    style='{')


class Remote(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = None

    def data_received(self, data):
        self.server_transport.write(data)


class Server(asyncio.Protocol):
    INIT, CONNECTING_TARGET, RELAY = range(3)

    def connection_made(self, transport):
        sslocal_info = transport.get_extra_info('peername')
        logging.debug('shadowsocks local {}'.format(sslocal_info))
        self.transport = transport
        self.state = self.INIT
        self.data_len = 0
        self.data_buf = b''

    def data_received(self, data):
        if self.state == self.INIT:
            self.data_buf += data
            self.data_len += len(data)
            addr_len = self.data_buf[0]
            if self.data_len < 1 + addr_len + 2:
                return None
            else:
                addr = self.data_buf[1:1 + addr_len]
                _port = self.data_buf[1 + addr_len:3 + addr_len]
                port = struct.unpack('>H', _port)
                port = port[0]

            logging.debug('target: {}:{}'.format(addr, port))

            # buffer the content which sends with target message
            if self.data_buf[1 + addr_len:3 + addr_len] != self.data_buf[-2:]:
                self.data_buf = self.data_buf[3 + addr_len:]

            else:
                # clear buffer and counter
                self.data_len = 0
                self.data_buf = b''

            # connect to taeget
            self.target = asyncio.ensure_future(self.connect(addr, port))
            self.state = self.CONNECTING_TARGET

        elif self.state == self.CONNECTING_TARGET:
            self.data_buf += data
            if self.target.done():    # connected target
            # There are 2 cases:
            # Connected to target before call it, so data in buffer will send
            # to target and buffer will be empty. (else case)
            #
            # Buffer the data after connected to target, so it will send data
            # to target. (if case)
                if self.data_buf == b'':
                    self.state = self.RELAY
                else:
                    self.remote_transport.write(self.data_buf)
                    self.state = self.RELAY

                logging.info('start relay')

        elif self.state == self.RELAY:
            self.remote_transport.write(data)

    async def connect(self, addr, port):
        logging.debug('connecting target')
        loop = asyncio.get_event_loop()
        transport, remote = await loop.create_connection(Remote, addr, port)
        remote.server_transport = self.transport    # set target_transport
        self.remote_transport = transport    # set remote_transport
        logging.debug('target connected')
        if self.data_buf:
            self.remote_transport.write(self.data_buf)
        self.data_buf = b''


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

    loop = asyncio.get_event_loop()
    server = loop.create_server(Server, '0.0.0.0', SERVER_PORT)
    loop.run_until_complete(server)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        server.close()
        loop.run_until_complete(server.close())
        loop.close()

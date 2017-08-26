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


class Server:

    async def sock2remote(self):
        pass

    async def remote2sock(self):
        pass

    async def handle(self, reader, writer):
        iv = await reader.read(16)
        self.Encrypt = aes_cfb(KEY, iv)
        self.Decrypt = aes_cfb(KEY, iv)

        _addr_len = await reader.read(1)
        _addr_len = self.Decrypt.decrypt(_addr_len)
        addr_len = struct.unpack('>B', _addr_len)
        _addr = await reader.read(addr_len)
        addr = self.Decrypt.decrypt(_addr)

        _port = await.reader.read(2)
        _port = self.Decrypt.decrypt(_port)
        port = struct.unpack('>H', _port)

        try:
            r_reader, r_writer = await asyncio.open_connection(addr, port)

        except OSError as e:
            logging.error(e)
            writer.close()
            return None

        self.reader = reader
        self.writer = writer
        self.r_reader = r_reader
        self.r_writer = r_writer




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

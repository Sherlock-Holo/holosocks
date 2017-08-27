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


async def handle(reader, writer):
    iv = await reader.read(16)
    Encrypt = aes_cfb(KEY, iv)
    Decrypt = aes_cfb(KEY, iv)

    _addr_len = await reader.read(1)
    _addr_len = Decrypt.decrypt(_addr_len)
    addr_len = struct.unpack('>B', _addr_len)[0]

    _addr = await reader.read(addr_len)
    addr = Decrypt.decrypt(_addr)

    _port = await reader.read(2)
    _port = Decrypt.decrypt(_port)
    port = struct.unpack('>H', _port)[0]

    logging.debug('target {}:{}'.format(addr, port))

    try:
        r_reader, r_writer = await asyncio.open_connection(addr, port)

    except OSError as e:
        logging.error(e)
        writer.close()
        return None

    async def sock2remote():
        while True:
            try:
                data = await reader.read(8192)

            except OSError as e:
                logging.error(e)
                break

            if not data:
                break

            else:
                r_writer.write(Decrypt.decrypt(data))
                await r_writer.drain()

    async def remote2sock():
        while True:
            try:
                data = await r_reader.read(8192)

            except OSError as e:
                logging.error(e)
                break

            if not data:
                break

            else:
                writer.write(Encrypt.encrypt(data))
                await writer.drain()

    def close_sock(future):
        writer.close()
        r_writer.close()
        logging.debug('relay stop')

    logging.debug('start relay')

    s2r = asyncio.ensure_future(sock2remote())
    r2s = asyncio.ensure_future(remote2sock())

    s2r.add_done_callback(close_sock)
    r2s.add_done_callback(close_sock)


if __name__ == '__main__':
    #logging.info('start shadowsocks server')
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
    coro = asyncio.start_server(handle, SERVER, SERVER_PORT)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

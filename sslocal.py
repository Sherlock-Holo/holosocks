#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import socket
import struct

from encrypt import aes_cfb

logging.basicConfig(level=logging.DEBUG,
                    format='{asctime} {levelname} {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    style='{')


async def handle(reader, writer):
    logging.debug('connect from {}'.format(writer.get_extra_info('peername')))
    request = await reader.read(2)
    if request[0] != 5:
        writer.close()
        logging.error('socks version not support')
        return None
    else:
        nmethods = request[1]
        logging.debug('methods number: {}'.format(nmethods))
        methods = await reader.read(nmethods)
        if 0 in methods:
            writer.write(b'\x05\x00')
            await writer.drain()
        else:
            writer.write(b'\x05\xff')
            logging.error('Authentication not support')
            writer.close()
            return None

    data = await reader.read(4)
    ver, cmd, rsv, atyp = data
    if cmd != 1:
        data = []
        data.append(b'\x05\x07\x00\x01')
        data.append(socket.inet_aton('0.0.0.0'))
        data.append(struct.pack('>H', 0))
        writer.write(b''.join(data))
        writer.close()
        logging.error('cmd not support')
        return None
    else:
        if atyp == 1:
            _addr = await reader.read(4)
            addr = socket.inet_ntoa(_addr).encode()

        elif atyp == 3:
            addr_len = await reader.read(1)
            addr = await reader.read(ord(addr_len))

        elif atyp == 4:
            _addr = await reader.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, _addr).encode()

        else:
            response = [
                b'\x05\x08\x00\x01',
                socket.inet_aton('0.0.0.0'),
                struct.pack('>H', 0)
            ]
            writer.write(b''.join(response))
            writer.close()
            return None

        _port = await reader.read(2)
        port = struct.unpack('>H', _port)[0]
        logging.debug('remote: {}:{}'.format(addr, port))

        target = [
            struct.pack('>B', len(addr)),
            addr,
            _port
        ]
        target = b''.join(target)

        try:
            r_reader, r_writer = await asyncio.open_connection(
                SERVER,
                SERVER_PORT
            )

        except OSError as e:
            logging.error(e)
            writer.close()
            return None

        if atyp != 4:
            data = [
                b'\x05\x00\x00\x01',
                socket.inet_aton('0.0.0.0'),
                struct.pack('>H', 0)
            ]
            writer.write(b''.join(data))
            await writer.drain()

        else:
            data = [
                b'\x05\x00\x00\x04',
                socket.inet_pton(socket.AF_INET6, '::'),
                struct.pack('>H', 0)
            ]
            writer.write(b''.join(data))
            await writer.drain()

        Encrypt = aes_cfb(KEY)
        iv = Encrypt.iv
        Decrypt = aes_cfb(KEY, iv)

        r_writer.write(iv)
        r_writer.write(Encrypt.encrypt(target))
        await r_writer.drain()

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
                    r_writer.write(Encrypt.encrypt(data))
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
                    writer.write(Decrypt.decrypt(data))
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
    #logging.info('start shadowsocks local')
    parser = argparse.ArgumentParser(description='shadowsocks local')
    parser.add_argument('-c', '--config', help='config file')
    args = parser.parse_args()
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    SERVER = config['server']
    SERVER_PORT = config['server_port']
    LOCAL = config['local']
    PORT = config['local_port']
    KEY = config['password']

    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle, LOCAL, PORT, loop=loop)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

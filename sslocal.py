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


class Remote(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = None

    def data_received(self, data):
        self.server_transport.write(data)


class Server(asyncio.Protocol):
    INIT, REQUEST, REPLY = range(3)

    def connection_made(self, transport):
        client_info = transport.get_extra_info('peername')
        logging.debug('connect from {}'.format(client_info))
        self.transport = transport
        self.state = self.INIT
        self.data_len = 0
        self.data_buf = b''

    def data_received(self, data):
        if self.state == self.INIT:
            # recv all ask data
            self.data_buf += data
            self.data_len += len(data)
            if self.data_len < 2:
                return None
            else:
                amount = self.data_buf[1]    # Authentication amount
                if self.data_len < 2 + amount:
                    return None

            if self.data_buf[0] == 5:    # version check
                if 0 in self.data_buf[2:]:    # no authentication
                    self.transport.write(b'\x05\x00')
                    self.state = self.REQUEST
                    # clear buffer and counter
                    self.data_len = 0
                    self.data_buf = b''

                else:
                    # authentication not support
                    response = struct.pack('>BB', 0x05, 0xff)
                    logging.error('authentication not support')
                    self.transport.write(response)
                    self.eof_received()
            else:
                self.eof_received()

        elif self.state == self.REQUEST:
            self.data_buf += data
            self.data_len += len(data)
            if self.data_len < 4:
                return None
            else:
                ver, cmd, rsv, addr_type = self.data_buf[:4]
                logging.debug('addr type: {}'.format(addr_type))

                if addr_type == 1:    # ipv4
                    # (ver cmd rsv atyp) addr_ip port
                    if self.data_len < 4 + 8 + 2:
                        return None
                    else:
                        addr = socket.inet_ntoa(self.data_buf[4:8])
                        port = struct.unpack('>H', self.data_buf[-2:])[0]
                        addr_len = struct.pack('>B', len(addr))
                        # target message: addr_len + addr + port
                        target = addr_len + addr.encode()
                        target += self.data_buf[-2:]

                elif addr_type == 3:    # domain name
                    if self.data_len < 4 + 1:
                        return None
                    else:
                        addr_len = self.data_buf[4]
                        if self.data_len < 5 + addr_len + 2:
                            return None
                        else:
                            addr = self.data_buf[5:5 + addr_len]
                            port = struct.unpack('>H', self.data_buf[-2:])[0]
                            # target message: addr_len + addr + port
                            # use socks5 raw message
                            target = self.data_buf[4:]

                else:    # addr type not support
                    response = b'\x05\x08\x00\x01'
                    response += socket.inet_aton('0.0.0.0')
                    response += struct.pack('>H', 0)
                    self.transport.write(response)
                    logging.error('addr type not support')
                    self.eof_received()

            logging.debug('target: {}:{}'.format(addr, port))

            # connect to shadowsocks server
            asyncio.ensure_future(self.connect(SERVER, SERVER_PORT, target))
            self.state = self.REPLY
            # clear buffer and counter, actually it is not important here
            self.data_len = 0
            self.data_buf = b''
            logging.info('start relay')

        elif self.state == self.REPLY:
            self.remote_transport.write(data)

    async def connect(self, addr, port, target):
        loop = asyncio.get_event_loop()
        transport, remote = await loop.create_connection(Remote, addr, port)
        remote.server_transport = self.transport
        self.remote_transport = transport
        self.remote_transport.write(target)    # send target message
        response = b'\x05\x00\x00\x01'
        response += socket.inet_aton('0.0.0.0') + struct.pack('>H', 0)
        self.transport.write(response)    # send response to socks5 client


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

    loop = asyncio.get_event_loop()
    server = loop.create_server(Server, '127.0.0.2', PORT)
    loop.run_until_complete(server)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        server.close()
        loop.run_until_complete(server.close())
        loop.close()

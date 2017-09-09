#!/usr/bin/env python3

import argparse
import asyncio
import functools
import json
import logging
import struct

try:
    from .encrypt import aes_cfb
except ModuleNotFoundError:  # develop mode
    from encrypt import aes_cfb

logging.basicConfig(
    level=logging.INFO,
    format='{asctime} {levelname} {message}',
    datefmt='%Y-%m-%d %H:%M:%S',
    style='{')


class Server:
    S2R, R2S = range(2)

    def __init__(self, key):
        self.key = key

    async def handle(self, reader, writer):
        try:
            iv = await reader.read(16)
            Encrypt = aes_cfb(self.key, iv)
            Decrypt = aes_cfb(self.key, iv)

            _addr_len = await reader.read(1)
            _addr_len = Decrypt.decrypt(_addr_len)
            addr_len = struct.unpack('>B', _addr_len)[0]

            _addr = await reader.read(addr_len)
            addr = Decrypt.decrypt(_addr)

            _port = await reader.read(2)
            _port = Decrypt.decrypt(_port)
            port = struct.unpack('>H', _port)[0]

            logging.debug('target {}:{}'.format(addr, port))

        except OSError as e:
            logging.error(e)
            writer.close()
            return None

        except ConnectionError as e:
            logging.error(e)
            writer.close()
            return None

        except TimeoutError as e:
            logging.error(e)
            writer.close()
            return None

        try:
            r_reader, r_writer = await asyncio.open_connection(addr, port)

        except OSError as e:
            logging.error(e)
            writer.close()
            return None

        except ConnectionError as e:
            logging.error(e)
            writer.close()
            return None

        except TimeoutError as e:
            logging.error(e)
            writer.close()
            return None

        logging.debug('start relay')

        s2r = asyncio.ensure_future(
            self.relay(reader, r_writer, Decrypt, self.S2R))

        r2s = asyncio.ensure_future(
            self.relay(r_reader, writer, Encrypt, self.R2S))

        s2r.add_done_callback(
            functools.partial(self.close_transport, writer, r_writer))

        r2s.add_done_callback(
            functools.partial(self.close_transport, writer, r_writer))

    async def relay(self, reader, writer, cipher, mode):
        while True:
            try:
                data = await reader.read(8192)

                if not data:
                    break

                else:
                    if mode == self.S2R:
                        writer.write(cipher.decrypt(data))
                    elif mode == self.R2S:
                        writer.write(cipher.encrypt(data))

                    await writer.drain()

            except OSError as e:
                logging.error(e)
                break

            except ConnectionError as e:
                logging.error(e)
                break

            except TimeoutError as e:
                logging.error(e)
                break

    def close_transport(self, writer, r_writer, future):
        writer.close()
        r_writer.close()


def main():
    #logging.info('start shadowsocks server')
    parser = argparse.ArgumentParser(description='holosocks server')
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
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logging.info('use uvloop event loop instead of asyncio event loop')
    except ImportError:
        logging.info('not found uvloop, use asyncio event lopp')
        pass

    server = Server(KEY)
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(server.handle, (SERVER, '::'), SERVER_PORT)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    main()

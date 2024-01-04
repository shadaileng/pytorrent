#!/usr/bin/python3
# -*- coding: utf-8 -*-

import urllib, socket, asyncio, time, logging, json
import download, utils
from torrent import BObject, TorrentFile, parse
from torrent import unmarshal, BtSrc, dump_data, buildPeerInfo
from download import MsgType, read_msg, write_msg, download_index, check_piece, download_index_async, fillBitfield, Bitfield
from urllib import request

def test(path):
    result = BObject()
    with open(path, 'rb') as src:
        # print(src.read().decode('utf-8', errors='ignore'))
        # result = parse(src)
        result = unmarshal(BtSrc(src.read()))
    return result

def test_get(url, params):
    # url = f'https://www.runoob.com/?s={request.quote("Python 教程") }'
    # req = request.Request(url)
    req = request.Request(url, urllib.parse.urlencode(params).encode('ascii'))
    rsp = request.urlopen(req).read()
    print(rsp)


def tets_get_aiohttp(url, params):
    import asyncio
    result = asyncio.run(download_task(url, params))
    print(result)

def test_find_peers_local():
    with open('data.txt', 'rb') as src:
        result = unmarshal(BtSrc(src.read())).value[b'peers'].value
        peerInfo = buildPeerInfo(result)
        print(peerInfo)

def test_find_peers():
    path = 'testfile/debian-iso.torrent'
    # path = 'testfile/Sintel.torrent'
    # path = 'testfile/ubuntu-22.10-desktop-amd64.iso.torrent'

    # bobject = test(path)
    # print(bobject.simple_value)
    # print(get_bytes(path, 11, 44))

    torrentFile = TorrentFile(path)
    print(torrentFile.simple_value)
    # torrentFile.parseFile()
    # url , params = torrentFile.makeurl()
    # print(url, params)
    # test_get(url, params)
    # tets_get_aiohttp(url, params)
    # test_find_peers()
    peers = torrentFile.find_peers()

def test_check_peers():
    path = 'testfile/debian-iso.torrent'
    torrentFile = TorrentFile(path)
    logging.info(torrentFile.simple_value)
    logging.info(asyncio.run(torrentFile.check_peers()))
    
    # peers = torrentFile.find_peers()
    # print(peers)
    # print(len(peers))

    # async def main_():
    #     tasks = [torrentFile.handshake_async(peer) for peer in peers[:5]]
    #     result = await asyncio.gather(*tasks)
    #     logging.info(f"result: {result}")
    # asyncio.run(main_())

def test_download_index(index = 1):
    path = 'testfile/debian-iso.torrent'
    # path = 'testfile/JUL-592.torrent'
    torrentFile = TorrentFile(path)
    logging.info(torrentFile.simple_value)
    infos = torrentFile.new_infos()
    peer = ('144.76.37.253', 56881)
    peer = ('185.189.112.27', 39129)
    conn = torrentFile.handshake(peer)

    bitfield = fillBitfield(conn)
    write_msg(conn, {"Id": MsgType.MsgInterested.value, "Payload": b''})
    if bitfield.has_pices(index):
        info = infos[index]
        print(info)
        asyncio.run(download_index_async(conn, info))
    else:
        logging.info(f"no index: {index}")

def test_data():
    path = 'testfile/debian-iso.torrent'
    # path = 'testfile/JUL-592.torrent'
    torrentFile = TorrentFile(path)
    logging.info(torrentFile.simple_value)
    print(torrentFile.new_infos("dist")[0])

    # print(utils.loaddata(f"{path}.info")[142])
    # print(utils.loaddata(f"{path}.status"))

def test_download_main():
    path = 'testfile/debian-iso.torrent'
    # path = 'testfile/JUL-592.torrent'
    torrentFile = TorrentFile(path)
    logging.info(torrentFile.simple_value)
    infos = torrentFile.new_infos()
    # [{('195.154.251.120', 6881): 0.4239165782928467}, {('185.189.112.27', 39129): 0.4326808452606201}]
    peer = ('185.189.112.27', 39129)
    conn = torrentFile.handshake(peer)
    bitfield = fillBitfield(conn)
    if bitfield is not None:
        asyncio.run(download.main(path, infos, conn, bitfield))


    # asyncio.run(download.main(path, infos, None, None))

def test_check_piece_sha(index = 1):
    path = 'testfile/debian-iso.torrent'
    torrentFile = TorrentFile(path)
    logging.info(torrentFile.simple_value)
   
    with open(f'{index}.data', 'rb') as f:
        data = f.read()
        logging.info(torrentFile.piecesha[index], check_piece(data))
        logging.info(torrentFile.piecesha[index] == check_piece(data))


def test_torrent_file():
    path = 'testfile/debian-iso.torrent'
    # path = 'testfile/JUL-592.torrent'
    # path = 'testfile/Sintel.torrent'
    torrentFile = TorrentFile(path)
    logging.info(json.dumps(torrentFile.simple_value))
    logging.info(torrentFile.single_to_dict())
    '''
    logging.info(torrentFile.info.value.keys())
    print("=" * 40)
    for item in torrentFile.info.value[b"files"].value:
        for key, val in item.value.items():
            print(f"{key}: {val.value}")
        print("-" * 20)
    logging.info(torrentFile.info.value[b"name"])
    print("=" * 40)
    for item in torrentFile.info.value[b"files"].value:
        if b'ed2k' in item.value.keys():
            # import binascii, hashlib
            # print(hashlib.sha1(item.value[b'filehash'].value).hexdigest())
            # print(binascii.hexlify(item.value[b'filehash'].value).decode('utf-8'))
            # print(len(item.value[b'ed2k'].value))
            # print(len(item.value[b'filehash'].value))
            print(f"ed2k://|file|{item.value[b'path'].value[0].value.decode('utf-8')}|{item.value[b'length'].value}|{item.value[b'ed2k'].value.hex()}|/")
        for key, item in item.value.items():
            if key.decode("utf-8").startswith('path'):
                print(key)
                for item in item.value:
                    print(item.value.decode("utf-8"))
            else:
                print(f"{key}: {item.value}")
            print("-" * 10)
        print("=" * 20)
    print("=" * 40)

    '''

if __name__ == '__main__':
    # test_check_piece_sha()
    # test_download_index(12)
    # test_check_peers()
    test_download_main()
    # test_data()

    # test_torrent_file()

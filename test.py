#!/usr/bin/python3
# -*- coding: utf-8 -*-

import urllib, socket, asyncio, time, logging, json
from urllib import request
from pytorrent import download, utils
from pytorrent.torrent import BObject, TorrentFile, parse
from pytorrent.torrent import unmarshal, BtSrc, dump_data, buildPeerInfo
from pytorrent.download import MsgType, read_msg, write_msg, download_index, check_piece, download_index_async, fillBitfield, Bitfield

def test():
    path = 'testfile/debian-iso.torrent'
    result = BObject()
    with open(path, 'rb') as src:
        # print(src.read().decode('utf-8', errors='ignore'))
        # result = parse(src)
        result = unmarshal(BtSrc(src.read()))
    logging.info(result)
    return result

def test_find_peers_local():
    with open('tmp/data.txt', 'rb') as src:
        result = unmarshal(BtSrc(src.read())).value[b'peers'].value
        peerInfo = buildPeerInfo(result)
        print(peerInfo)

def test_find_peers():
    path = 'testfile/debian-iso.torrent'
    # path = 'testfile/Sintel.torrent'
    # path = 'testfile/ubuntu-22.10-desktop-amd64.iso.torrent'
    torrentFile = TorrentFile(path)
    logging.info(torrentFile.simple_value)
    peers = torrentFile.find_peers()
    logging.info(peers)

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

def test_torrent_file():
    path = 'testfile/debian-iso.torrent'
    # path = 'testfile/JUL-592.torrent'
    # path = 'testfile/Sintel.torrent'
    torrentFile = TorrentFile(path)
    logging.info(json.dumps(torrentFile.simple_value))
    logging.info(torrentFile.single_to_dict())

if __name__ == '__main__':
    # test()
    # test_find_peers_local()
    # test_find_peers()
    # test_download_index()
    # test_data()
    # test_download_main()
    test_torrent_file()
    

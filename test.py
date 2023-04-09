#!/usr/bin/python3
# -*- coding: utf-8 -*-

import urllib
from torrent import BObject, TorrentFile, parse, unmarshal, BtSrc
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


async def download_task(url, params, resultObj={}, headers={}):
    import aiohttp, logging
    from aiohttp import TCPConnector
    from yarl import URL
    connector = TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=True) as session:
        try:
            logging.info(f"get: {url}, {params}")
            url = URL(f"{url}?{'&'.join([f'{key}={val}'for key, val in params.items()])}", encoded=True)
            async with session.get(url, headers=headers) as resp:
                print(resp.url)
                if resp.status in (206, 200):
                    result = unmarshal(BtSrc(await resp.read()))
                    print(result)
        except BaseException as e:
            logging.error(e)


def tets_get_aiohttp(url, params):
    import asyncio
    asyncio.run(download_task(url, params))

if __name__ == '__main__':
    path = 'testfile/debian-iso.torrent'
    path = 'testfile/Sintel.torrent'
    path = 'testfile/ubuntu-22.10-desktop-amd64.iso.torrent'

    # bobject = test(path)
    # print(bobject.single_to_dict())
    # print(BObjectEncoder().encode(bobject))
    # print(get_bytes(path, 11, 44))

    torrentFile = TorrentFile(path)
    # print(torrentFile.single_to_dict())
    url , params = torrentFile.makeurl()
    # print(url, params)
    # test_get(url, params)
    tets_get_aiohttp(url, params)


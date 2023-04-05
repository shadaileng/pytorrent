#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re, json, hashlib, random, urllib, ssl
from json import JSONEncoder
from urllib import request

class BObject(object):
    def __init__(self, type=None, value=None, start=0, length=0):
        self.type = type
        self.value = value
        self.start = start
        self.length = length

    def __repr__(self):
        return str(self.single_to_dict())

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)

    def single_to_dict(self):
        # return {'type': self.type, 'value': self.value}
        return {'type': self.type, 'start': self.start, 'length': self.length, 'value': self.value}

class BObjectEncoder(JSONEncoder):
        def default(self, o):
            return o.__dict__

class TorrentFile(dict):
    def __init__(self, path):
        self.parseFile(path)

    def single_to_dict(self):
        return {'announce': self.announce, 'infosha': self.infosha, 'filename': self.filename, 'filelen': self.filelen, 'piecelen': self.piecelen, 'piecesha': self.piecesha}
    
    def parseFile(self, path):
        SHALEN = 20
        result = test(path).value
        info = result.get(b'info')
        sha1 = hashlib.sha1()
        sha1.update(get_bytes(path, info.start, info.length))
        print(request.quote(get_bytes(path, info.start, info.length)))
        bys = info.value.get(b'pieces').value
        cnt = len(bys) / SHALEN
        hashes = []
        for index in range(int(cnt)):
            hashes.append(bys[index*SHALEN:(index + 1)*SHALEN])
        self.piecesha = hashes

        self.announce = result.get(b'announce').value.decode('utf-8')
        if info:
            self.filename = info.value.get(b'name').value.decode('utf-8')
            self.filelen = info.value.get(b'length', 0).value
            self.piecelen = info.value.get(b'piece length', 0).value
        self.infosha = sha1.hexdigest()

    def makeurl(self, path= None):
        if path is not None:
            self.parseFile(path)
        PeerPort = 6666
        peerId = "".join(list(map(lambda x: chr([random.randint(ord("a"), ord("z")), random.randint(ord("0"), ord("9"))][random.randint(0, 1)]), range(20))))
        url = self.announce
        print(request.quote('解码'))
        params = {
            "info_hash":  request.quote(self.infosha),
            "peer_id":    peerId,
            "port":       PeerPort,
            "uploaded":   "0",
            "downloaded": "0",
            "compact":    "1",
            "left":       self.filelen,
        }
        return (url, params)

def read_decimal(src):
    sign = 1
    dec_len = 0
    val = 0
    flag = src.read(1)
    dec_len += 1
    if flag == b'-':
        sign = -1
        dec_len += 1
        # 第一位数字
        flag = src.read(1)
    while True:
        # print(f'flag: {flag}')
        if flag < b'0' or flag > b'9':
            src.seek(-1, 1)
            dec_len -= 1
            break
        val = val * 10 + int(flag.decode('utf-8'))
        flag = src.read(1)
        dec_len += 1
    return val * sign, dec_len

def decode_string(src):
    val = None
    num, dec_len = read_decimal(src)
    # print(f'num: {num}, dec_len: {dec_len}')
    if dec_len == 0: return val
    flag = src.read(1)
    if flag != b':': 
        return val
    val = src.read(num)
    # val = src.read(num).decode('utf-8')
    # val = src.read(num).decode('gbk')
    # val = src.read(num).decode('utf-8', errors='ignore')
    return val

def get_bytes(path, start, length):
    with open(path, 'rb') as src:
        src.seek(start, 0)
        return src.read(length)


def parse(src):
    result = BObject()
    result.start = src.tell()
    b = src.read(1).decode('utf-8')
    offset = src.tell()
    if b == 'l':
        list_ = []
        while True:
            flag = src.read(1)
            if b'e' == flag: break
            src.seek(-1, 1)
            list_.append(parse(src))
        result.type = 'list'
        result.value = list_
        result.length = src.tell() - offset + 1
    if b == 'd':
        dictionary = {}
        i = 0
        while True:
            flag = src.read(1)
            if b'e' == flag: break
            src.seek(-1, 1)
            key = decode_string(src)
            # print(f'key: {key}')
            dictionary[key] = parse(src)
            # break
            i += 1
        result.type = 'dict'
        result.value = dictionary
        result.length = src.tell() - offset + 1
    if b == 'i':
        num, dec_len = read_decimal(src)
        flag = src.read(1)
        # print(f'flag: {flag}, {b"e" == flag}')
        if b'e' != flag: 
            result.value = 0
        result.value = num
        result.type = 'int'
        result.length = src.tell() - offset + 1
    if re.match('[0-9]', b):
        src.seek(-1, 1)
        result.type = 'str'
        result.value = decode_string(src)
        result.length = src.tell() - offset + 1
    # print(result)
    return result

def parse_(src):
    result = {}
    result['start'] = src.tell()
    b = src.read(1).decode('utf-8')
    offset = src.tell()
    if b == 'l':
        list_ = []
        while True:
            flag = src.read(1)
            if b'e' == flag: break
            src.seek(-1, 1)
            list_.append(parse(src))
        result['type'] = 'list'
        result['value'] = list_
        result['length'] = src.tell() - offset + 1
    if b == 'd':
        dictionary = {}
        i = 0
        while i < 5:
            flag = src.read(1)
            if b'e' == flag: break
            src.seek(-1, 1)
            key = decode_string(src)
            # print(f'key: {key}')
            dictionary[key] = parse(src)
            # break
            i += 1
        result['type'] = 'dict'
        result['value'] = dictionary
        result['length'] = src.tell() - offset + 1
    if b == 'i':
        num, dec_len = read_decimal(src)
        flag = src.read(1)
        # print(f'flag: {flag}, {b"e" == flag}')
        if b'e' != flag: 
            result['value'] = 0
        result['value'] = num
        result['type'] = 'int'
        result['length'] = src.tell() - offset + 1
    if re.match('[0-9]', b):
        src.seek(-1, 1)
        result['type'] = 'str'
        result['value'] = decode_string(src)
        result['length'] = src.tell() - offset + 1
        # if result['length'] > 100: result['value'] = b'111'
    # print(result)
    return result

def test(path):
    result = BObject()
    with open(path, 'rb') as src:
        # print(src.read().decode('utf-8', errors='ignore'))
        result = parse(src)
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
    connector = TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=True) as session:
        try:
            logging.info(f"get: {url}, {params}")
            async with session.get(url, params=params, headers=headers) as resp:
                if resp.status in (206, 200):
                    result = await resp.json()
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
    print(url, params)
    # test_get(url, params)
    tets_get_aiohttp(url, params)


#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re, json, hashlib, random
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
        with open(path, 'rb') as src:
            result = parse(src).value
        if result is None: return
        info = result.get(b'info')
        sha1 = hashlib.sha1()
        sha1.update(get_bytes(path, info.start, info.length))
        print('-'*20)
        print(request.quote(sha1.digest()))
        print('-'*20)
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
        # self.infosha = sha1.hexdigest()
        # self.infosha = request.quote(sha1.digest())
        self.infosha = sha1.digest()

    def makeurl(self, path= None):
        if path is not None:
            self.parseFile(path)
        PeerPort = 6666
        peerId = "".join(list(map(lambda x: chr([random.randint(ord("a"), ord("z")), random.randint(ord("0"), ord("9"))][random.randint(0, 1)]), range(20))))
        url = self.announce
        params = {
            "info_hash":  request.quote(self.infosha),
            # "info_hash":  self.infosha,
            "peer_id":    peerId,
            "port":       PeerPort,
            "uploaded":   "0",
            "downloaded": "0",
            "compact":    "1",
            "left":       self.filelen,
        }
        return (url, params)

class BtSrc(object):
    def __init__(self, text=b'', index = 0) -> None:
        self.text = text
        self.index = index
    def peek(self):
        return self.text[self.index]
    def get(self, length=1):
        result = self.text[self.index : self.index + length]
        self.index += length
        return result
    def back(self, length=1):
        self.index -= length
    
def unmarshal_string(src=BtSrc()):
    val = None
    num, dec_len = unmarshal_decimal(src)
    # print(f'num: {num}, dec_len: {dec_len}')
    if dec_len == 0: return val
    flag = src.get()
    if flag != b':': 
        return val
    val = src.get(num)
    # val = src.read(num).decode('utf-8')
    # val = src.read(num).decode('gbk')
    # val = src.read(num).decode('utf-8', errors='ignore')
    return val

def unmarshal_decimal(src=BtSrc()):
    sign = 1
    dec_len = 0
    val = 0
    flag = src.get()
    dec_len += 1
    if flag == b'-':
        sign = -1
        dec_len += 1
        # 第一位数字
        flag = src.get()
    while True:
        # print(f'flag: {flag}')
        if flag < b'0' or flag > b'9':
            src.back()
            dec_len -= 1
            break
        val = val * 10 + int(flag.decode('utf-8'))
        flag = src.get()
        dec_len += 1
    return val * sign, dec_len

def unmarshal(src=BtSrc()):
    result = BObject()
    b = src.get()
    offset = src.index
    if b == b'l':
        list_ = []
        while True:
            flag = src.get()
            if b'e' == flag: break
            src.back()
            list_.append(unmarshal(src))
        result.type = 'list'
        result.value = list_
        result.length = src.index - offset + 1
    if b == b'd':
        dictionary = {}
        i = 0
        while True:
            flag = src.get(1)
            if b'e' == flag: break
            src.back()
            key = unmarshal_string(src)
            # print(f'key: {key}')
            dictionary[key] = unmarshal(src)
            # break
            i += 1
        result.type = 'dict'
        result.value = dictionary
        result.length = src.index - offset + 1
    if b == b'i':
        num, dec_len = unmarshal_decimal(src)
        flag = src.get(1)
        if b'e' != flag: 
            result.value = 0
        result.value = num
        result.type = 'int'
        result.length = src.index - offset + 1
    if re.match('[0-9]', b.decode('utf-8', errors='ignore')):
        src.back()
        result.type = 'str'
        result.value = unmarshal_string(src)
        result.length = src.index - offset + 1
    # print(result)
    return result


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

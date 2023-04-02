#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re, json
from json import JSONEncoder

class BObject(object):
    def __init__(self, type=None, value=None, length=0):
        self.type = type
        self.value = value
        self.length = length

    def __repr__(self):
        return str(self.single_to_dict())

    def toJson(self):
            return json.dumps(self, default=lambda o: o.__dict__)

    def single_to_dict(self):
        return {'type': self.type, 'value': self.value}
        # return {'type': self.type, 'value': self.value, 'length': self.length}

class BObjectEncoder(JSONEncoder):
        def default(self, o):
            return o.__dict__

class TorrentFile(dict):
    def __init__(self):
        self.announce = None
        self.infosha = None
        self.filename = None
        self.filelen = None
        self.piecelen = None
        self.piecesha = None

    def parseFile(self, path):
        bobject = test(path)
        self.announce = bobject.value.get(b'announce', b'').decode('utf-8')
        info = bobject.value.get(b'info', {})
        self.filename = info.get(b'name', b'').decode('utf-8')
        self.filelen = info.get(b'length', 0)
        self.piecelen = info.get(b'piece length', 0)
        # self.infosha = bobject.value.get('announce', None)
        self.piecesha = info.get(b'pieces', None)

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

def parse(src):
    result = BObject()
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
        while i < 5:
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

def test(path):
    result = BObject()
    with open(path, 'rb') as src:
        # print(src.read().decode('utf-8', errors='ignore'))
        result = parse(src)
    return result

if __name__ == '__main__':
    path = 'testfile/debian-iso.torrent'
    bobject = test(path)
    print(bobject.single_to_dict())
    # print(BObjectEncoder().encode(bobject))
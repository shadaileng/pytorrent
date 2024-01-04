#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re, json, hashlib, random, struct, socket, urllib, os, time,sys
from enum import Enum
from json import JSONEncoder
from urllib import request

import aiohttp, asyncio, logging
from aiohttp import TCPConnector
from yarl import URL
from . import utils
from .logger import set_logger

set_logger()

SHALEN = 20
IpLen = 4
PortLen =2
PeerLen = IpLen + PortLen
Reserved = 8
IDLEN = 20
HsMsgLen = SHALEN + IDLEN + Reserved

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

def parse_bobj(item):
    if item.type in 'str':
        try:
            return item.value.decode("utf-8")
        except Exception:
            return item.value
    if item.type == 'int':
        return item.value
    if item.type == 'list':
        return [parse_bobj(item) for item in item.value]
    if item.type == 'dict':
        return {key.decode("utf-8"): parse_bobj(val) for key, val in item.value.items()}

def parse_bobj_simple(item):
    if item.type in 'str':
        try:
            return item.value.decode("utf-8")
        except Exception:
            return item.value.hex()
    if item.type == 'int':
        return item.value
    if item.type == 'list':
        return [parse_bobj_simple(item) for item in item.value]
    if item.type == 'dict':
        return {key.decode("utf-8"): (parse_bobj_simple(val) if key.decode("utf-8") != 'pieces' else f"{val.value[:20].hex()}...") for key, val in item.value.items()}


class TorrentFile(dict):
    def __init__(self, path, port=6666):
        self.parseFile(path)
        self.path = path
        self.PeerPort = port
        self.peerId = "".join(list(map(lambda x: chr([random.randint(ord("a"), ord("z")), random.randint(ord("0"), ord("9"))][random.randint(0, 1)]), range(20))))

    def single_to_dict(self):
        files = []
        info = self.value["info"]
        if "files" in info.keys():
            for file in info["files"]:
                if "ed2k" in file.keys():
                    filename = os.path.join(*([info["name"]] + file['path']))
                    files.append({
                        "url": f"ed2k://|file|{filename}|{file['length']}|{file['ed2k'].hex()}|/",
                        "filehash": file["filehash"].hex(),
                        "path": filename,
                    })
        else:
            files.append({
                "url": self.makeurl(),
                "filehash": hashlib.sha1(info["pieces"]).hexdigest(),
                "path": self.value["info"]["name"],
            })
        return {
            'files': files, 
            'infoSha': self.infoSha, 
            'filelen': self.filelen, 
            'piecelen': self.piecelen, 
            # 'piecesha': [item.hex() for item in self.piecesha]
        }
        # return {'announce': self.announce, 'infoSha': self.infoSha, 'filename': self.filename, 'filelen': self.filelen, 'piecelen': self.piecelen, 'piecesha': self.piecesha}

    def parseFile(self, path):
        '''
        解析文件
        '''
        with open(path, 'rb') as src:
            # result = parse(src).value
            result = unmarshal(BtSrc(src.read()))
            self.value = parse_bobj(result)
            self.simple_value = parse_bobj_simple(result)
            result = result.value
        if result is None: return
        info = result.get(b'info')
        sha1 = hashlib.sha1()
        sha1.update(get_bytes(path, info.start, info.length))
        bys = info.value.get(b'pieces').value
        cnt = len(bys) / SHALEN
        hashes = []
        for index in range(int(cnt)):
            hashes.append(bys[index*SHALEN:(index + 1)*SHALEN])
        self.piecesha = hashes

        self.announce = result.get(b'announce', BObject(value= b'')).value.decode('utf-8')
        if info:
            self.filename = info.value.get(b'name').value.decode('utf-8')
            self.filelen = info.value.get(b'length', BObject(value= 0)).value
            self.piecelen = info.value.get(b'piece length', 0).value
        # self.infoSha = sha1.hexdigest()
        # self.infoSha = request.quote(sha1.digest())
        self.infoSha = sha1.digest()
        self.info = info

    def new_infos(self, dist=None):
        path = self.path
        if dist is not None:
            path = os.path.join(dist, os.path.basename(self.path))
        infos = utils.loaddata(f"{path}.info")
        if infos is not None: 
            for index, item in infos.items():
                if item["Status"] in (0, -2):
                    item["Status"] = -1
                    item["Error"] = None
            return infos
        name = os.path.splitext(path)[0]
        return {index: self.new_info(f"{name}_{index}.data", index, self.piecelen, piece_sha) for index, piece_sha in enumerate(self.piecesha)}


    def new_info(self, output, index, length, piece_sha, BLOCK_SIZE = 10240):    
        num = int(length / BLOCK_SIZE )
        if length % BLOCK_SIZE != 0:
            num += 1
        info = {
            "Key": index,
            "Output": output,
            "Length": length,
            "DownLen": 0,
            "TOTAL": {i * BLOCK_SIZE: BLOCK_SIZE if (i + 1) * BLOCK_SIZE < length else length - i * BLOCK_SIZE for i in range(num)},
            "SEND": {},
            "RECV": {},
            "Scale": 0.0,
            "Status": -1,
            "Piecesha": piece_sha,
            "Error": None,
            "Retry": 5
        }
        return info


    def makeurl(self):
        '''
        解析tracker请求地址和参数
        '''
        url = self.announce
        params = {
            # "info_hash":  request.quote(self.infoSha),
            "info_hash":  self.infoSha,
            "peer_id":    self.peerId,
            "port":       self.PeerPort,
            "uploaded":   "0",
            "downloaded": "0",
            "compact":    "1",
            "left":       self.filelen,
        }
        return (url, urllib.parse.urlencode(params))

    def find_peers(self):
        '''
        从announce获取peers
        '''
        result = None
        url, params = self.makeurl()
        result = asyncio.run(download_task(url, params))
        print(result)
        if result is None: []
        # with open('data.txt', 'rb') as src:
        #     result = src.read()
        # peers主机列表刷新时间间隔/s
        interval = unmarshal(BtSrc(result)).value[b'interval'].value
        peers = unmarshal(BtSrc(result)).value[b'peers'].value
        return self.buildPeerInfo(peers)

    async def find_peers_async(self):
        '''
        从announce获取peers
        '''
        result = None
        url, params = self.makeurl()
        result = await download_task(url, params)
        print(result)
        if result is None: []
        # with open('data.txt', 'rb') as src:
        #     result = src.read()
        # peers主机列表刷新时间间隔/s
        interval = unmarshal(BtSrc(result)).value[b'interval'].value
        peers = unmarshal(BtSrc(result)).value[b'peers'].value
        return self.buildPeerInfo(peers)

    def buildPeerInfo(self, bytes):
        '''
        从peers解析IP地址和端口
        '''
        if len(bytes) % PeerLen != 0: return []
        num = len(bytes) / PeerLen
        peers = []
        for index in range(0, len(bytes), PeerLen):
            ip = bytes[index:index+IpLen]
            port = bytes[index+IpLen:index+PeerLen]
            # print((ip, port))
            # int.to_bytes(length, byteorder, *, signed=False)
            # int.from_bytes(bytes, byteorder, *, signed=False)
            peers.append(('.'.join(map(str, struct.unpack('B' * IpLen, ip))), int.from_bytes(port, byteorder='big')))
        return peers
    
    def make_handshake_req(self):
        self.hankshake_req = {'PreStr':  "BitTorrent protocol", 'InfoSHA': self.infoSha, 'PeerId':  self.peerId}
        logging.info(f'hankshake_req: {self.hankshake_req}')
        return (chr(len(self.hankshake_req['PreStr'])) + self.hankshake_req['PreStr'] + chr(0) * Reserved ).encode('utf-8')+ self.infoSha  + self.peerId.encode("utf-8")
        
    def handshake(self, peer):
        '''
        和peers握手
        '''
        # '''
        # peers = self.find_peers()
        # peers = [('185.125.190.59', 6943)]
        req = self.make_handshake_req()
        logging.info(f'peers: {peer}, req: {req}')
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(15)
        # 建立连接:
        try:
            # conn.connect(('144.76.37.253', 56881))
            conn.connect(peer)
            conn.send(req)
            # 接收数据:
            prelen = int(conn.recv(1)[0])
            if prelen <= 0:
                logging.warning(f"读取长度失败: {prelen}")
                return
            PreStr = conn.recv(prelen).decode('utf-8')
            logging.info(f"PreStr: {PreStr}")
            _ = conn.recv(Reserved)
            InfoSHA = conn.recv(SHALEN)
            PeerId = conn.recv(IDLEN)
            self.hankshake_rsp = {'PreStr': PreStr, 'InfoSHA': InfoSHA, 'PeerId': PeerId.decode('utf-8')}
            logging.info(f'hankshake_req: {self.hankshake_req}')
            if self.hankshake_req['InfoSHA'] != self.hankshake_rsp['InfoSHA']:
                logging.warning('InfoSHA验证失败')
                return
            logging.warning(f'InfoSHA验证成功: {self.hankshake_rsp}')
            return conn
        except Exception as e:
            logging.warning(f'[-]Error[{__file__},line: {sys.exc_info()[2].tb_lineno}]: {e}')

    async def handshake_async(self, peer):
        '''
        和peers握手
        '''
        print(peer)
        req = self.make_handshake_req()
        logging.info(f'peers: {peer}, req: {req}')
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(15)
        start = time.time()
        # 建立连接:
        try:
            # conn.connect(('144.76.37.253', 56881))
            conn.connect(peer)
            conn.send(req)
            # 接收数据:
            prelen = int(conn.recv(1)[0])
            if prelen <= 0:
                logging.warning(f"读取长度失败: {prelen}")
                return
            PreStr = conn.recv(prelen).decode('utf-8')
            logging.info(f"PreStr: {PreStr}")
            _ = conn.recv(Reserved)
            InfoSHA = conn.recv(SHALEN)
            PeerId = conn.recv(IDLEN)
            self.hankshake_rsp = {'PreStr': PreStr, 'InfoSHA': InfoSHA, 'PeerId': PeerId.decode('utf-8')}
            logging.info(f'hankshake_req: {self.hankshake_req}')
            if self.hankshake_req['InfoSHA'] != self.hankshake_rsp['InfoSHA']:
                logging.warning('InfoSHA验证失败')
                return
            logging.warning(f'InfoSHA验证成功: {self.hankshake_rsp}')
            return conn, {peer: time.time() - start}
        except Exception as e:
            logging.warning(f'[-]Error[{__file__},line: {sys.exc_info()[2].tb_lineno}]: {e}')
        return None, {peer: time.time() - start}

    async def check_peers(self)->dict:
        peers = await self.find_peers_async()
        tasks = [self.handshake_async(peer) for peer in peers[:10]]
        result = await asyncio.gather(*tasks)
        return [spend for conn, spend in result if conn is not None]


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


async def download_task(url, params, resultObj={}, headers={}):
    connector = TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=True) as session:
        try:
            # url = URL(f"{url}?{'&'.join([f'{key}={val}'for key, val in paramconn.items()])}", encoded=True)
            url = f'{url}?{params}'
            logging.info(f"get: {url}")
            async with session.get(url, headers=headers) as resp:
                if resp.status in (206, 200):
                    result = await resp.read()
                    # dump_data('data.txt', result)
                    return result
        except BaseException as e:
            logging.error(e)




def buildPeerInfo(bytes):
    if len(bytes) % PeerLen != 0: return []
    num = len(bytes) / PeerLen
    peers = []
    for index in range(0, len(bytes), PeerLen):
        ip = bytes[index:index+IpLen]
        port = bytes[index+IpLen:index+PeerLen]
        # print((ip, port))
        peers.append(('.'.join(map(str, struct.unpack('B' * IpLen, ip))), int(''.join(map(str, struct.unpack('B' * PortLen, port))))))
    return peers

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
    result.start = src.index
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

def dump_data(filename, data={}):
    with open(filename, 'wb') as dst:
        dst.seek(0)
        dst.truncate()
        dst.write(data)
        dst.flush()

def parse2dict(src):
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

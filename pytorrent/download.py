#!/usr/bin/python3
# -*- coding: utf-8 -*-
import json, hashlib, struct, socket, os, time, asyncio, logging
from enum import Enum
from .utils import loaddata, dumpdata, byteunit

def new_req_msg(index, offset, length):
    buf = bytearray(12)
    put_be(buf, index, 4)
    put_be(buf, offset, 4, 4)
    put_be(buf, length, 4, 8)
    return {"Id": MsgType.MsgRequest.value, "Payload": buf} 

def pase_req_msg(buf):
    index = get_be(buf[:4])
    offset = get_be(buf[4:8])
    length = get_be(buf[8:])
    logging.info(f"index: {index}, offset: {offset}, length: {length}")

def download_index(conn, index, offset, length, piecesha):
    choked = False
    flag = 1500
    BLOCK_SIZE = 10240
    saved = 0
    while flag > 0 and saved < length:
        if not choked and offset < length:
            dleng = BLOCK_SIZE
            if length - offset < BLOCK_SIZE:
                dleng = length - offset
            logging.info(f"[MsgRequest]index: {index}, offset: {offset}, length: {dleng}, total: {length}")
            write_msg(conn, new_req_msg(index, offset, dleng))
            offset += dleng
        msg = read_msg(conn)
        if msg is None:
            logging.warning("msg is None")
            flag -= 1
            continue
        if msg["Id"] == MsgType.MsgChoke.value:
            choked = True
            logging.info(f"[MsgChoke]choked: {choked}")
        if msg["Id"] == MsgType.MsgUnchoke.value:
            choked = False
            logging.info(f"[MsgUnchoke]choked: {choked}")
        if msg["Id"] == MsgType.MsgHave.value:
            index = get_be(msg["Payload"])
            logging.info("[MsgHave]index: {index}")
        if msg["Id"] == MsgType.MsgPiece.value:
            # logging.info(msg["Payload"])
            parsedIndex = get_be(msg["Payload"][:4])
            parsedOffset = get_be(msg["Payload"][4:8])
            data = msg["Payload"][8:]
            filename = f"{index}.data"
            if not os.path.exists(filename):
                fp = open(filename, "wb")
                fp.truncate(length)
                fp.close()
            with open(filename, "r+b") as dst:
                dst.seek(parsedOffset, 0)
                dst.write(data)
                saved += len(data)
            logging.info(f"[MsgPiece]index: {parsedIndex}, saved: {saved}, {saved}/{length}={int(saved / length * 10000) / 100}%, offset: {parsedOffset}, data: {data[:10]}...")
            flag += 1
            if piecesha == check_piece(open(filename, "rb").read()):
                logging.info("[SHA]验证成功,退出")
                break
        time.sleep(.1)
    if flag == 0:
        logging.info("[-]异常退出")

async def download_index_async(conn, info):
    while info["Retry"] > 0 and info["Status"] in (-1, 0):
        try:
            info["Status"] = 0
            await download_async(conn, info)
        except Exception as e:
            info["Error"] = str(e)
            if info["Retry"] > 0:
                info["Retry"] -= 1
                logging.info(f"Error: {e}, remain: {info['Retry']}")
            else:
                info["Status"] = -2
    logging.info(info)

async def download_async(conn, info):
    choked = False
    flag = 15000
    BLOCK_MAX = 5
    saved = 0
    index = info["Key"]
    length = info["Length"]
    offset_list = list(info["TOTAL"].keys())
    offset_index = 0
    block = 0
    
    while flag > 0 and saved < length:
        if not choked and block < BLOCK_MAX and offset_index < len(offset_list):
            offset = offset_list[offset_index]
            if offset not in info["SEND"].keys():
                dleng = info["TOTAL"][offset]
                logging.info(f"[MsgRequest]index: {index}, offset: {offset}, length: {dleng}, total: {length}")
                write_msg(conn, new_req_msg(index, offset, dleng))
                info["SEND"][offset] = dleng
                block += 1
            offset_index += 1
        msg = await read_msg_async(conn)
        if msg is None:
            # logging.warning("msg is None")
            flag -= 1
            await asyncio.sleep(1)
            continue
        if msg["Id"] == MsgType.MsgChoke.value:
            choked = True
            logging.info(f"[MsgChoke]choked: {choked}")
        if msg["Id"] == MsgType.MsgUnchoke.value:
            choked = False
            logging.info(f"[MsgUnchoke]choked: {choked}")
        if msg["Id"] == MsgType.MsgHave.value:
            index = get_be(msg["Payload"])
            logging.info("[MsgHave]index: {index}")
        if msg["Id"] == MsgType.MsgPiece.value:
            # logging.info(msg["Payload"])
            parsedIndex = get_be(msg["Payload"][:4])
            parsedOffset = get_be(msg["Payload"][4:8])
            data = msg["Payload"][8:]
            # filename = f"{index}.data"
            filename = info["Output"]
            if not os.path.exists(filename):
                fp = open(filename, "wb")
                fp.truncate(length)
                fp.close()
            with open(filename, "r+b") as dst:
                dst.seek(parsedOffset, 0)
                dst.write(data)
                saved += len(data)
            block -= 1
            info["RECV"][offset] = dleng
            info["DownLen"] = saved
            info["Scale"] = int(saved / length * 10000) / 100
            logging.info(f"[MsgPiece]index: {parsedIndex}, saved: {saved}, {saved}/{length}={int(saved / length * 10000) / 100}%, offset: {parsedOffset}, data: {data[:10]}...")
            flag += 1
            if info["Piecesha"] == check_piece(open(filename, "rb").read()):
                info["Status"] = 1
                info["DownLen"] = info["Length"]
                info["Scale"] = 1.0
                logging.info("[SHA]验证成功,退出")
                break
        time.sleep(.1)
    if flag == 0:
        logging.info("[-]异常退出")
        info["Status"] = -2


def fillBitfield(conn):
    if conn is None: return
    msg = read_msg(conn)
    if msg is None: return
    if msg["Id"] != MsgType.MsgBitfield.value: return
    return Bitfield(msg["Payload"])

def read_msg(conn)->dict:
    flag = 15
    buf_length = b''
    while flag > 0 and len(buf_length) != 4:
        buf_length += conn.recv(4)
        flag -= 1
    # logging.info(f"recv: {buf}")
    if flag == 0: 
        return 
    length = get_be(buf_length)
    logging.error(f"length: {length}, buf_length: {buf_length}")
    if length == 0:
        return
    buf = b''
    flag = 50
    while flag > 0 and len(buf) != length:
        buf_ = conn.recv(length)
        # logging.error(f"buf_: {len(buf_)}, {length}, {length == len(buf_)}")
        # buf.append(buf_)
        buf+=buf_
        flag -= 1
    if flag == 0: 
        logging.error(f"failed to recv {length}: {buf}")
        return
    logging.error(f"buf: {len(buf)}, {length}, {length == len(buf)}")
    buf_str = f"{buf_length}|{buf}" if len(buf) < 20 else f"{buf_length}|{buf[:20]}..."
    msg = {"Id": buf[0], "Payload": buf[1:]}
    Payload_str = f"{msg['Payload']}" if len(msg['Payload']) < 10 else f"{msg['Payload'][:10]}..."
    logging.info(f"recv:Id: {msg['Id']}, Payload: {Payload_str},  {buf_str}")
    return msg

async def read_msg_async(conn)->dict:
    flag = 15
    buf_length = b''
    while flag > 0 and len(buf_length) != 4:
        buf_length += conn.recv(4)
        flag -= 1
    # logging.info(f"recv: {buf}")
    if flag == 0: 
        return 
    length = get_be(buf_length)
    logging.error(f"length: {length}, buf_length: {buf_length}")
    if length == 0:
        return
    buf = b''
    flag = 50
    while flag > 0 and len(buf) != length:
        buf_ = conn.recv(length)
        # logging.error(f"buf_: {len(buf_)}, {length}, {length == len(buf_)}")
        # buf.append(buf_)
        buf+=buf_
        flag -= 1
    if flag == 0: 
        logging.error(f"failed to recv {length}: {buf}")
        return
    logging.error(f"buf: {len(buf)}, {length}, {length == len(buf)}")
    buf_str = f"{buf_length}|{buf}" if len(buf) < 20 else f"{buf_length}|{buf[:20]}..."
    msg = {"Id": buf[0], "Payload": buf[1:]}
    Payload_str = f"{msg['Payload']}" if len(msg['Payload']) < 10 else f"{msg['Payload'][:10]}..."
    logging.info(f"recv:Id: {msg['Id']}, Payload: {Payload_str},  {buf_str}")
    return msg

def read(buf):
    print(buf)
    length = get_be(buf[:4])
    logging.info(f"length: {length}")
    buf = buf[4:]
    if buf[0] == 6:
        pase_req_msg(buf[1:])
    print({"Id": buf[0], "Payload": buf[1:]})

def write_msg(conn:socket.socket, msg:dict):
    logging.info(f"send: {msg}")
    length = len(msg["Payload"]) + 1
    buf = bytearray(length + 4)
    put_be(buf, length, 4)
    buf[4] = msg["Id"]
    buf[5:] = msg["Payload"]
    # read(buf)

    conn.send(buf)
    return buf

def put_be(byte_array, value, length, offset=0):
    packed = struct.pack('>I', value)  # '>I' 表示大端字节序的无符号整数，将 value 打包为 4 字节的大端字节序
    byte_array[offset:offset+length] = packed  # 将打包后的字节流放入 byte_array 的指定偏移位置
    return offset + length  # 返回新的偏移位置

def get_be(byte_array):
    return struct.unpack('>I', byte_array)[0]

def check_piece(data):
    return hashlib.sha1(data).digest()

class MsgType(Enum):
	# MsgChoke表示阻塞
	MsgChoke       = 0
	# MsgUnchoke表示解除阻塞
	MsgUnchoke     = 1
	# MsgInterested表示信息相关
	MsgInterested  = 2
	# MsgNotInterested表示信息不相关
	MsgNotInterest = 3
	# MsgHave表示提醒接收者，发送者拥有资源
	MsgHave        = 4
	# MsgBitfield表示发送者拥有资源的哪些部分
	MsgBitfield    = 5
	# MsgRequest表示向接收方请求数据
	MsgRequest     = 6
	# MsgPiece表示发送数据以完成请求
	MsgPiece       = 7
	# MsgCancel表示取消一个请求
	MsgCancel      = 8
    

class Bitfield(object):
    def __init__(self, bitfield: list) -> None:
        self.bitfield = bitfield
        self.length = len(bitfield) * 8
        self.bitfield_len = len(bitfield)
        self.pices_has = self.have()

    def has_pices(self, index: int)->bool:
        b_index = index // 8
        b_offset = index % 8
        return self.bitfield[b_index] >> (7 - b_offset) & 1 == 1

    def set_pices(self, index: int)->None:
        b_index = index // 8
        b_offset = index % 8
        self.bitfield[b_index] |= 1 << (7 - b_offset)
    def have(self)->list:
        return [i for i in range(len(self.bitfield) * 8) if self.has_pices(i)]

    def __str__(self):
        return "piece# " + (",".join(map(str, self.pices_has)))


async def main(outputPath:str, infos: dict, conn: socket.socket, bitfield: Bitfield, threadNum:int=5, verbose=True):
    tasks = asyncio.Queue(threadNum)
    create = asyncio.Queue()
    status = asyncio.Queue()
    download_tasks = []
    for index in range(threadNum):
        download_tasks.append(task_comsume(index, conn, tasks, status, create))
    logging.info("开始下载")
    tasks_working = [task_creat(infos, bitfield, threadNum, tasks, status, create), task_status(outputPath, infos, status, verbose=verbose)] + download_tasks
    await asyncio.gather(*tasks_working)
    logging.info("下载完成")

async def task_comsume(task_id: int, conn: socket.socket, tasks: asyncio.Queue, status: asyncio.Queue, create: asyncio.Queue):
    while True:
        info = await tasks.get()
        if info is None:
            logging.info(f"tasks recive None, exit the task_comsume_{ task_id }")
            break
        if info["Status"] != 0:
            continue
        await download_index_async(conn, info)
        await create.put(1)
        # logging.info(f"task_comsume_{ task_id } put 1")
    logging.info(f"task_comsume_{ task_id } exit")

async def task_creat(infos: dict, bitfield:Bitfield, threadNum: int, tasks: asyncio.Queue, status: asyncio.Queue, create: asyncio.Queue):
    flag = True
    for key, info in infos.items():
        if bitfield is None or not bitfield.has_pices(key):
            info["Status"] = -2
            info["Error"] = f"bitfield not include: {key}"
            await tasks.put(info)
        if info["Status"] == -1:
            flag = False
            info["Status"] = 0
            info["Error"] = None
            await tasks.put(info)
    
    while not flag:
        creat_info = await create.get()
        # logging.info(f"task_creat get 1")
        if creat_info is None: break
        flag = True
        for key, info in infos.items():
            if info["Status"] in (-1, 0):
                flag = False
                if info["Status"] == -1:
                    info["Status"] = 0
                    info["Error"] = None
                    await tasks.put(info)
    logging.info(f"task_creat exit")
    # 所有运行中任务已结束 关闭任务队列
    # logging.info(f"All download task finished, put {threadNum} None into tasks")
    await asyncio.gather(*[tasks.put(None) for i in range(threadNum)])
    # 所有下载任务完成 关闭status队列
    # logging.info("All download task finished, put None into status")
    # await status.put(None)

async def task_status(outputPath: str, infos: dict, status: asyncio.Queue, *, verbose: bool=False, speed: dict={"now": 0.0, "last": 0.0, "nTotal": 0.0, "lTotal": 0.0}):
    while True:
        try:
            info = await asyncio.wait_for(status.get(), timeout=1)
            if info is None:
                logging.info("status recive None, exit the task_status")
                break
        except asyncio.TimeoutError:
            # print('timeout!')
            pass
        flag = True
        downLen, length, chunks, avaible = 0, 0, 0, 0
        complete, error = 0, 0
        for key, info in infos.items():
            if info["Status"] in (-1, 0):
                flag = False
                avaible += 1
            if info["Status"] == 1:
                complete += 1
            if info["Status"] == -2:
                error += 1
            downLen += info["DownLen"]
            length += info["Length"]
            chunks += 1
        
        if time.time() - speed["now"] > 0.5:
            speed["last"] = speed["now"]
            speed["lTotal"] = speed["nTotal"]
            speed["nTotal"] = downLen
            speed["now"] = time.time()
        dtl = (speed["nTotal"]-speed["lTotal"]) if (speed["nTotal"]-speed["lTotal"]) > 0 else 0
        speed_val = dtl/(speed["now"]-speed["last"]) if speed["now"] != speed["last"] else 0
        status_data = {
            "Output": outputPath,
            "Chunks": chunks,
            "Avaible": avaible,
            "Complete": complete,
            "Error": error,
            "Size": length,
            "DSize": downLen,
            "Speed": speed,
            "Scale": downLen/length if length > 0 else 0,
        }
        status_info = "Output: %s, Chunks: %d, Avaible: %d, Complete: %d, Error: %d, Size: %d, DSize: %d, Speed: %s\t%.2f%%" % (outputPath, chunks, avaible, complete, error, length, downLen, f"{byteunit(speed_val)}/s", downLen/length*100 if length > 0 else 0)
        if verbose:
            logging.info(status_info)
        # 缓存下载信息及状态
        dumpdata(f"{outputPath}.info", infos)
        dumpdata(f"{outputPath}.status", status_data)
        if flag: 
            logging.info(f"[+]Download Finished!")
            break

# -*- coding: utf-8 -*-

import logging, json, sys, pickle, os
from typing import Any


def byteunit(byte):
    return '%.2fKB' % (byte / 1024.0) if byte / 1024.0 < 1024 else ('%.2fMB' % (byte / 1024.0 / 1024.0) if (byte / 1024.0 / 1024.0) < 1024 else '%.2fGB' % (byte / 1024.0 / 1024.0 / 1024.0))


def dumpdata(filename: str, data: Any):
    try:
        with open(filename, 'wb') as src:
            pickle.dump(data, src)
        return True
    except BaseException as e:
        logging.error('[-]Error[%s]: %s' % (sys.exc_info()[2].tb_lineno, e))
        if isinstance(e, KeyboardInterrupt): raise e
    return False

def loaddata(filename: str)->Any:
    try:
        if not os.path.exists(filename):
            return None
        with open(filename, 'rb') as src:
            return pickle.load(src)
    except Exception as e:
        # logging.error('[-]Error[%s]: %s' % (sys.exc_info()[2].tb_lineno, e))
        if isinstance(e, KeyboardInterrupt): raise e
    return None

def dumpjson(filename: str, data: Any):
    try:
        with open(filename, 'w') as src:
            src.truncate(0)
            json.dump(data, src)
        return True
    except BaseException as e:
        logging.error('[-]Error[%s]: %s' % (sys.exc_info()[2].tb_lineno, e))
        if isinstance(e, KeyboardInterrupt): raise e
    return False

def loadjson(filename: str)->Any:
    try:
        if not os.path.exists(filename):
            return None
        with open(filename, 'r') as src:
            return json.load(src)
    except BaseException as e:
        # logging.error('[-]Error[%s]: %s' % (sys.exc_info()[2].tb_lineno, e))
        if isinstance(e, KeyboardInterrupt): raise e
    return None

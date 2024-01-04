import logging
import os
import time

formatter = "%(asctime)s - %(filename)s, line:%(lineno)d - %(levelname)s: %(message)s"

def log_file(log_path=None):
    # 创建写入文件的handler
    if not log_path:
        log_path = 'log'
    os.makedirs(log_path, exist_ok=True)
    log_name = log_path + '/%s.log'
    map = {logging.DEBUG: 'debug', logging.INFO: 'info', logging.WARN: 'warn', logging.ERROR: 'error'}
    fhs = []
    for level in map.keys():
        fh = logging.FileHandler(log_name % map[level], mode='a')
        fh.setLevel(level)
        # 定义日志文件输出格式
        fh.setFormatter(logging.Formatter(formatter))
        fhs.append(fh)

    return fhs


def log_cmd():
    # 创建控制台handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(formatter))

    return ch


def set_logger(log_path=None):
    # 创建logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # 将logger添加到handler里面
    for fh in log_file(log_path):
        logger.addHandler(fh)
    logger.addHandler(log_cmd())

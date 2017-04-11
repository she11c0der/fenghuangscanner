#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan rsync弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import time
import threading
import sys
import socket
from comm.printers import printPink, printGreen
from multiprocessing.dummy import Pool
from Queue import Queue

socket.setdefaulttimeout(10)
sys.path.append("../")


class MyPoc(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.sp = Queue()

    def rsync_connect(self, ip, port):
        """
        rsync连接
        :param ip:
        :param port:
        :return:
        """
        creak = 0
        try:
            payload = '\x40\x52\x53\x59\x4e\x43\x44\x3a\x20\x33\x31\x2e\x30\x0a'
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(8)
            s.connect((ip, int(port)))
            s.sendall(payload)
            time.sleep(2)
            # server init.
            initinfo = s.recv(400)
            if "RSYNCD" in initinfo:
                s.sendall("\x0a")
                time.sleep(2)
            modulelist = s.recv(200)
            # print modulelist
            if len(modulelist) > 0:
                for i in modulelist.split("\n"):
                    # 模块保存到list中
                    if i != "" and i.find("@RSYNCD") < 0:
                        self.lock.acquire()
                        printGreen("%s rsync at %s find a module\r\n" % (ip, port))
                        self.result.append("%s rsync at %s find a module\r\n" % (ip, port))
                        self.lock.release()
        except Exception, e:
            print e
            pass
        return creak

    def rsync_creak(self, ip, port):
        try:
            self.rsync_connect(ip, port)
        except Exception, e:
            print e

    def run(self, ip_dict, threads, filename):
        """
        主函数
        :param ip_dict:
        :param threads:
        :param filename:
        :return:
        """
        if 'rsync' in ip_dict:
            printPink("crack rsync  now...")
            print "[*] start crack rsync  %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ip_dict['rsync']:
                pool.apply_async(func=self.rsync_creak, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()

            print "[*] stop rsync serice  %s" % time.ctime()
            print "[*] crack rsync done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    from comm.config import *

    c = Config()
    ipdict = {'rsync': ['103.228.69.151:873']}
    test = MyPoc(c)
    test.run(ipdict, 50, filename="../result/test")

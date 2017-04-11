#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan ftp弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""

import time
import threading
from multiprocessing.dummy import Pool
from comm.printers import printPink, printGreen
from ftplib import FTP


class MyPoc(object):
    """
    ftp弱口令扫描插件
    """

    def __init__(self, c):
        """
        初始化
        :param c:
        """
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/ftp.conf")

    def ftp_connect(self, ip, username, password, port):
        """
        ftp 链接函数
        :param ip:
        :param username:
        :param password:
        :param port:
        :return:
        """
        crack = 0
        try:
            ftp = FTP()
            ftp.connect(ip, str(port))
            ftp.login(user=username, passwd=password)
            crack = 1
            ftp.close()
        except:
            self.lock.acquire()
            print "%s ftp service 's %s:%s login fail " % (ip, username, password)
            self.lock.release()
        return crack

    def ftp_l(self, ip, port):
        """
        读文件爆破
        :param ip:
        :param port:
        :return:
        """
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                if self.ftp_connect(ip, username, password, port) == 1:
                    self.lock.acquire()
                    printGreen("%s ftp at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "%s ftp at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
        except:
            pass

    def run(self, ipdict, threads, filename):
        """
        主函数
        :param ipdict:
        :param pinglist:
        :param threads:
        :param filename:
        :return:
        """
        if "ftp" in ipdict:
            printPink("crack ftp  now...")
            print "[*] start crack ftp  %s" % time.ctime()
            start_time = time.time()

            pool = Pool(threads)

            for ip in ipdict['ftp']:
                pool.apply_async(func=self.ftp_l, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()

            print "[*] stop ftp serice  %s" % time.ctime()
            print "[*] crack ftp done,it has Elapsed time:%s " % (time.time() - start_time)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ip_dict = {'ftp': ['172.17.0.11:21']}
    test = MyPoc(c)
    test.run(ip_dict, 50, filename="../result/test")

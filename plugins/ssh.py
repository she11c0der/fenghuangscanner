#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan ssh弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import time
import threading
import paramiko
from multiprocessing.dummy import Pool
from comm.printers import printPink, printGreen


class MyPoc(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/ssh.conf")

    def ssh_connect(self, ip, username, password, port):
        """
        ssh 连接
        :param ip:
        :param username:
        :param password:
        :param port:
        :return:
        """
        crack = 0
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port, username=username, password=password)
            crack = 1
            client.close()
        except Exception, e:
            if e[0] == 'Authentication failed.':
                self.lock.acquire()
                print "%s ssh service 's %s:%s login fail " % (ip, username, password)
                self.lock.release()
            else:
                self.lock.acquire()
                print "connect %s ssh service at %s login fail " % (ip, port)
                self.lock.release()
                crack = 2
        return crack

    def ssh_l(self, ip, port):
        """
        ssh连接
        :param ip:
        :param port:
        :return:
        """
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.ssh_connect(ip, username, password, port)
                if flag == 2:
                    break
                if flag == 1:
                    self.lock.acquire()
                    printGreen("%s ssh at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "%s ssh at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
        except Exception, e:
            pass

    def run(self, ip_dict, threads, filename):
        """
        主函数
        :param ip_dict:
        :param threads:
        :param filename:
        :return:
        """
        if "ssh" in ip_dict:
            printPink("crack ssh  now...")
            print "[*] start crack ssh  %s" % time.ctime()
            start_time = time.time()

            pool = Pool(threads)

            for ip in ip_dict['ssh']:
                pool.apply_async(func=self.ssh_l, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()

            print "[*] stop ssh serice  %s" % time.ctime()
            print "[*] crack ssh done,it has Elapsed time:%s " % (time.time() - start_time)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ipdict = {'ssh': ['172.17.25.2:22']}
    test = MyPoc(c)
    test.run(ipdict, 50, filename="../result/test")

#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan smb弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import time
import threading
from comm.printers import printPink, printGreen
from impacket.smbconnection import *
from multiprocessing.dummy import Pool


class MyPoc(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/smb.conf")

    def smb_connect(self, ip, username, password):
        """
        smb连接
        :param ip:
        :param username:
        :param password:
        :return:
        """
        crack = 0
        try:
            smb_login = SMBConnection('*SMBSERVER', ip)
            # 这扫不了
            smb_login.login('shabi', 'shabidemimacaishizhege!@#!@S')
            smb_login.logoff()
            crack = 2
            return crack
        except:
            pass

        try:
            smb_login = SMBConnection('*SMBSERVER', ip)
            smb_login.login(username, password)
            smb_login.logoff()
        except Exception, e:
            print e
            self.lock.acquire()
            print "%s smb 's %s:%s login fail " % (ip, username, password)
            self.lock.release()
        return crack

    def smb_l(self, ip, port):
        """
        爆破
        :param ip:
        :param port:
        :return:
        """
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.smb_connect(ip, username, password)
                if flag == 1:
                    self.lock.acquire()
                    printGreen("%s smb at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "%s smb at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
                elif flag == 2:
                    print("can surport %s smb at %s" % (ip, port))
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
        if 'smb' in ip_dict:
            printPink("crack smb  now...")
            print "[*] start crack smb serice  %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ip_dict['smb']:
                pool.apply_async(func=self.smb_l, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()

            print "[*] stop smb serice  %s" % time.ctime()
            print "[*] crack smb  done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ipdict = {'smb': ['172.17.4.200:445']}
    test = MyPoc(c)
    test.run(ipdict, 50, filename="../result/test")

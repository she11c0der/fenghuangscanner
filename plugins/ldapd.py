#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan ldap弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""

import time
import threading
import ldap
from comm.printers import printPink, printGreen
from multiprocessing.dummy import Pool


class MyPoc(object):
    def __init__(self, c):
        """
        初始化
        :param c:
        """
        self.config = c
        self.lock = threading.Lock()
        self.result = []

    @staticmethod
    def ldap_connect(ip, port):
        """
        ldap连接
        :param ip:
        :param port:
        :return:
        """
        creak = 0
        try:
            ldap_path = 'ldap://' + ip + ':' + port + '/'
            l = ldap.initialize(ldap_path)
            l.simple_bind_s()
            creak = 1
        except Exception, e:
            if e[0]['desc'] == "Can't contact LDAP server":
                creak = 2
            pass
        return creak

    def ldap_creak(self, ip, port):
        """
        ldap连接
        :param ip:
        :param port:
        :return:
        """
        try:
            flag = self.ldap_connect(ip, port)
            if flag == 2:
                self.lock.acquire()
                printGreen("%s ldap at %s can't connect\r\n" % (ip, port))
                self.lock.release()

            if flag == 1:
                self.lock.acquire()
                printGreen("%s ldap at %s allow simple_bind\r\n" % (ip, port))
                self.result.append("%s ldap at %s allow simple_bind\r\n" % (ip, port))
                self.lock.release()
        except Exception, e:
            print e
            pass

    def run(self, ipdict, threads, filename):
        """
        主函数
        :param ipdict:
        :param threads:
        :param filename:
        :return:
        """
        if 'ldap' in ipdict:
            printPink("crack ldap  now...")
            print "[*] start ldap  %s" % time.ctime()
            start_time = time.time()

            pool = Pool(threads)

            for ip in ipdict['ldap']:
                pool.apply_async(func=self.ldap_creak, args=(str(ip).split(':')[0], str(ip).split(':')[1]))
            pool.close()
            pool.join()

            print "[*] stop ldap serice  %s" % time.ctime()
            print "[*] crack ldap done,it has Elapsed time:%s " % (time.time() - start_time)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ip_dict = {'ldap': ['172.17.0.7:389']}
    test = MyPoc(c)
    test.run(ip_dict, 50, filename="../result/test")

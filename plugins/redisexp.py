#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan redis弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import time
import threading
from threading import Thread
from comm.printers import printPink, printGreen
from Queue import Queue
import redis


class MyPoc(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/redis.conf")
        self.sp = Queue()

    def redis_exp(self):
        """
        爆破
        :return:
        """
        while True:
            ip, port = self.sp.get()
            try:
                r = redis.Redis(host=ip, port=port, db=0, socket_timeout=8)
                r.dbsize()
                self.lock.acquire()
                printGreen('%s redis service at %s allow login Anonymous login!!\r\n' % (ip, port))
                self.result.append('%s redis service at %s allow login Anonymous login!!\r\n' % (ip, port))
                self.lock.release()
            except Exception, e:
                if "Authentication" in e[0]:
                    # 爆破一下 2333
                    for data in self.lines:
                        try:
                            r = redis.Redis(host=ip, port=port, db=0, password=data, socket_timeout=8)
                            r.dbsize()
                            printGreen('%s redis service at %s port has weakpass:%s' % (ip, port, data))
                            self.result.append('%s redis service at %s port has weakpass:%s' % (ip, port, data))
                            break
                        except Exception, e:
                            print "[*] %s redis service 's at %s login with:%s fail,err:%s" % (ip, port, data, str(e))
            self.sp.task_done()

    def run(self, ip_dict, threads, filename):
        """
        主函数
        :param ip_dict:
        :param threads:
        :param filename:
        :return:
        """
        if 'redis' in ip_dict:
            printPink("crack redis  now...")
            print "[*] start crack redis  %s" % time.ctime()
            start_time = time.time()

            for i in xrange(threads):
                t = Thread(target=self.redis_exp)
                t.setDaemon(True)
                t.start()

            for ip in ip_dict['redis']:
                self.sp.put((str(ip).split(':')[0], int(str(ip).split(':')[1])))

            self.sp.join()

            print "[*] stop redis serice  %s" % time.ctime()
            print "[*] crack redis done,it has Elapsed time:%s " % (time.time() - start_time)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ipdict = {'redis': ['172.17.0.11:6379']}
    test = MyPoc(c)
    test.run(ipdict, 50, filename="../result/test")

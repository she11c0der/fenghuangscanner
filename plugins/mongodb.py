#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan mongodb弱口令检查
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import time
import threading
import pymongo
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
        self.lines = self.config.file2list("conf/mongodb.conf")

    def mongodb_connect(self, ip, username, password, port):
        """
        mongodb 连接字符串
        :param ip:
        :param username:
        :param password:
        :param port:
        :return:
        """
        crack = 0
        try:
            connection = pymongo.Connection(ip, port)
            db = connection.admin
            db.collection_names()
            self.lock.acquire()
            printRed('%s mongodb service at %s allow login Anonymous login!!\r\n' % (ip, port))
            self.result.append('%s mongodb service at %s allow login Anonymous login!!\r\n' % (ip, port))
            self.lock.release()
            crack = 1

        except Exception, e:
            if "not authorized" in e[0]:
                try:
                    r = db.authenticate(username, password)
                    if r != False:
                        crack = 2
                    else:
                        self.lock.acquire()
                        crack = 3
                        print "%s mongodb service 's %s:%s login fail " % (ip, username, password)
                        self.lock.release()
                except Exception, e:
                    pass

            else:
                print e
                printRed('%s mongodb service at %s not connect' % (ip, port))
                crack = 4
        return crack

    def mongo_db(self, ip, port):
        """
        连接
        :param ip:
        :param port:
        :return:
        """
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.mongodb_connect(ip, username, password, port)
                if flag in [1, 4]:
                    break

                if flag == 2:
                    self.lock.acquire()
                    printGreen(
                        "%s mongoDB at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "%s mongoDB at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
        except:
            pass

    def run(self, ip_dict, threads, filename):
        """
        主函数
        :param ip_dict:
        :param threads:
        :param filename:
        :return:
        """
        if 'mongodb' in ip_dict:
            printPink("crack mongodb  now...")
            print "[*] start crack mongodb  %s" % time.ctime()
            start_time = time.time()

            pool = Pool(threads)

            for ip in ip_dict['mongodb']:
                pool.apply_async(func=self.mongo_db, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()
            print "[*] stop mongoDB serice  %s" % time.ctime()
            print "[*] crack mongoDB done,it has Elapsed time:%s " % (time.time() - start_time)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ip_dict = {'mongodb': ['172.17.70.233:27017']}
    test = MyPoc(c)
    test.run(ip_dict, 50, filename="../result/test")

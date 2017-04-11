#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan vnc弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import requests
import time
import base64
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool


class MyPoc(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.tomcat_lines = self.config.file2list("conf/tomcat.conf")
        self.web_lines = self.config.file2list("conf/web.conf")

    def web_login(self, url, ip, port, username, password):
        """
        :param url:
        :param ip:
        :param port:
        :param username:
        :param password:
        :return:
        """
        creak = 0
        try:
            header = {}
            login_pass = username + ':' + password
            header['Authorization'] = 'Basic ' + base64.encodestring(login_pass)
            # header base64.encodestring 会多加一个回车号
            header['Authorization'] = header['Authorization'].replace("\n", "")
            r = requests.get(url, headers=header, timeout=8)
            if r.status_code == 200:
                self.result.append(
                    "%s service at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                self.lock.acquire()
                printGreen("%s service at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                self.lock.release()
                creak = 1
            else:
                self.lock.acquire()
                print "%s service 's %s:%s login fail " % (ip, username, password)
                self.lock.release()
        except Exception, e:
            pass
        return creak

    def web_main(self, ip, port):
        """
        web爆破
        :param ip:
        :param port:
        :return:
        """
        # iis_put vlun scann
        try:
            url = 'http://' + ip + ':' + str(port) + '/' + str(time.time()) + '.txt'
            r = requests.put(url, data='hi~', timeout=10)
            if r.status_code == 201:
                self.lock.acquire()
                printGreen('%s has iis_put vlun at %s\r\n' % (ip, port))
                self.lock.release()
                self.result.append('%s has iis_put vlun at %s\r\n' % (ip, port))
        except Exception, e:
            # print e
            pass

        # burp 401 web
        try:
            url = 'http://' + ip + ':' + str(port)
            url_get = url + '/manager/html'
            r = requests.get(url_get, timeout=8)  # tomcat
            r2 = requests.get(url, timeout=8)  # web

            if r.status_code == 401:
                for data in self.tomcat_lines:
                    username = data.split(':')[0]
                    password = data.split(':')[1]
                    flag = self.web_login(url_get, ip, port, username, password)
                    if flag == 1:
                        break

            elif r2.status_code == 401:
                for data in self.web_lines:
                    username = data.split(':')[0]
                    password = data.split(':')[1]
                    flag = self.web_login(url, ip, port, username, password)
                    if flag == 1:
                        break
            else:
                pass

        except Exception, e:
            pass

    def run(self, ip_dict, threads, filename):
        """
        爆破主函数
        :param ip_dict:
        :param threads:
        :param filename:
        :return:
        """
        if 'http' in ip_dict:
            print "[*] start test web burp at %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ip_dict['http']:
                pool.apply_async(func=self.web_main, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()

            print "[*] stop test iip_put&&scanner web paths at %s" % time.ctime()
            print "[*] test iip_put&&scanner web paths done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ipdict = {'http': ['127.0.0.1:80']}
    test = MyPoc(c)
    test.run(ipdict, 50, filename="../result/test")

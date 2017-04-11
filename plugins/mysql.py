#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan mysql弱口令扫描插件
    ~~~~~~~~~~~~~~~~~~~~
    参考：https://github.com/ysrc/xunfeng/blob/master/vulscan/vuldb/crack_mysql.py
    主函数
    :author = 'wilson'
"""

import time
import threading
import binascii
import hashlib
import struct
import socket
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
        self.lines = self.config.file2list("conf/mysql.conf")

    @staticmethod
    def get_hash(password, scramble):
        """
        :param password:
        :param scramble:
        :return:
        """
        hash_stage1 = hashlib.sha1(password).digest()
        hash_stage2 = hashlib.sha1(hash_stage1).digest()
        to = hashlib.sha1(scramble + hash_stage2).digest()
        reply = [ord(h1) ^ ord(h3) for (h1, h3) in zip(hash_stage1, to)]
        hash = struct.pack('20B', *reply)
        return hash

    @staticmethod
    def get_scramble(packet):
        """
        :param packet:
        :return:
        """
        tmp = packet[15:]
        m = re.findall("\x00?([\x01-\x7F]{7,})\x00", tmp)
        if len(m) > 3: del m[0]
        scramble = m[0] + m[1]
        try:
            plugin = m[2]
        except:
            plugin = ''
        return plugin, scramble

    def get_auth_data(self, user, password, scramble, plugin):
        """
        mysql连接
        :param user:
        :param password:
        :param scramble:
        :param plugin:
        :return:
        """
        user_hex = binascii.b2a_hex(user)
        pass_hex = binascii.b2a_hex(self.get_hash(password, scramble))
        if not password:
            data = "85a23f0000000040080000000000000000000000000000000000000000000000" + user_hex + "0000"
        else:
            data = "85a23f0000000040080000000000000000000000000000000000000000000000" + user_hex + "0014" + pass_hex
        if plugin: data += binascii.b2a_hex(
            plugin) + "0055035f6f73076f737831302e380c5f636c69656e745f6e616d65086c69626d7973716c045f7069640539323330360f5f636c69656e745f76657273696f6e06352e362e3231095f706c6174666f726d067838365f3634"
        len_hex = hex(len(data) / 2).replace("0x", "")
        auth_data = len_hex + "000001" + data
        return binascii.a2b_hex(auth_data)

    def mysql_connect(self, ip, username, password, port):
        """
        爆破
        :param ip:
        :param username:
        :param password:
        :param port:
        :return:
        """
        crack = 0
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, int(port)))
            packet = sock.recv(254)
            # print packet
            plugin, scramble = self.get_scramble(packet)
            auth_data = self.get_auth_data(username, password, scramble, plugin)
            sock.send(auth_data)
            result = sock.recv(1024)
            if result == "\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00":
                crack = 1
            else:
                self.lock.acquire()
                print "%s mysql's %s:%s login fail" % (ip, username, password)
                self.lock.release()
            sock.close()
        except Exception, e:
            if "timed out" in str(e) or "refused" in str(e):
                self.lock.acquire()
                print "connect %s mysql service at %s login fail " % (ip, port)
                self.lock.release()
                crack = 2
        return crack

    def mysq1(self, ip, port):
        """
        :param ip:
        :param port:
        :return:
        """
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.mysql_connect(ip, username, password, port)
                if flag == 2:
                    break

                if flag == 1:
                    self.lock.acquire()
                    printGreen("%s mysql at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "%s mysql at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
        except Exception, e:
            pass

    def run(self, ipdict, threads, filename):
        """
        主函数
        :param ipdict:
        :param threads:
        :param filename:
        :return:
        """
        if 'mysql' in ipdict:
            printPink("crack mysql now...")
            print "[*] start crack mysql %s" % time.ctime()
            start_time = time.time()

            pool = Pool(threads)
            for ip in ipdict['mysql']:
                pool.apply_async(func=self.mysq1, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()

            print "[*] stop crack mysql %s" % time.ctime()
            print "[*] crack mysql done,it has Elapsed time:%s " % (time.time() - start_time)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], filename=filename)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = Config()
    ip_dict = {'mysql': ['127.0.0.1:3306']}
    test = MyPoc(c)
    test.run(ip_dict, 50, filename="../result/test")

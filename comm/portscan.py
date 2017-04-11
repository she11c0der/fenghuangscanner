#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan PortScan
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import threading
import re
import time
import socket
import sys
import platform
from subprocess import Popen, PIPE
from comm.printers import printRed
from threading import Thread
from Queue import Queue

socket.setdefaulttimeout(10)  # 设置了全局默认超时时间


class PortScan(object):
    """端口扫描"""

    def __init__(self, c, user_ports):
        """
        初始化
        :param c:
        :param user_ports:
        """
        self.config = c
        self.probes = [
            "\r\n\r\n",
            "stats\r\n",
            "test\r\n",
            "ls\r\n",
            "GET / HTTP/1.0\r\n\r\n",
            "GET / HTTP/1.1\nuser-agent: Googlebot\n\n"
        ]

        self.signs_from_file = self.config.file2list("conf/signs.conf")
        self.ports = []
        self.get_ports(user_ports)
        self.lock = threading.Lock()
        self.ping_list = []
        self.q = Queue()
        self.sp = Queue()
        self.signs = self.prep_signs()
        self.ip_dict = {}

    def get_ports(self, user_ports):
        """
        获取扫描端口列表
        :param user_ports:
        :return:
        """
        if user_ports == '':
            # 文件中读，端口配置
            user_ports = open("conf/ports.conf", "r").read().replace("\r", "").replace("\n", "")
        try:
            self.ports = user_ports.split(",")
            remove_port = []
            for p in self.ports:
                if str(p).find("-") >= 0:
                    remove_port.append(str(p))
                    start = int(p.split("-")[0])
                    end = int(p.split("-")[1]) + 1
                    for i in range(start, end):
                        self.ports.append(i)
                else:
                    pass
            for repate in remove_port:
                self.ports.remove(repate)
        except:
            printRed('[!] not a valid ports given. you should put ip like 22,80,1433 or 22-1000')
            sys.exit()

    # ping扫描函数
    def pinger(self):
        """
        多线程继续ping扫描
        ping 扫描
        :return:
        """
        while True:
            ip = self.q.get()
            if platform.system() == 'Linux':
                p = Popen(['ping', '-c 2', ip], stdout=PIPE)
                m = re.search('(\d)\sreceived', p.stdout.read())
                try:
                    if m.group(1) != '0':
                        self.ping_list.append(ip)
                        self.lock.acquire()
                        printRed("%s is live!!\r\n" % ip)
                        self.lock.release()
                except:
                    pass

            if platform.system() == 'Darwin':
                import commands
                p = commands.getstatusoutput("ping -c 2 " + ip)
                m = re.findall('ttl', p[1])
                try:
                    if m:
                        self.ping_list.append(ip)
                        self.lock.acquire()
                        printRed("%s is live!!\r\n" % ip)
                        self.lock.release()
                except:
                    pass

            if platform.system() == 'Windows':
                p = Popen('ping -n 2 ' + ip, stdout=PIPE)
                m = re.findall('TTL', p.stdout.read())
                if m:
                    self.ping_list.append(ip)
                    self.lock.acquire()
                    printRed("%s is live!!\r\n" % ip)
                    self.lock.release()
            self.q.task_done()

    def ping_scan(self, isping, threads, ips):
        """
        ping_scan ping扫描
        :param isping:
        :param threads:
        :param ips:
        :return:
        """
        starttime = time.time()
        print "[*] start Scanning at %s" % time.ctime()
        # isping=='no' 就禁ping扫描
        # 默认ping 扫描
        if isping == 'yes':
            print "Scanning for live machines..."
            for i in xrange(threads):
                t = Thread(target=self.pinger)
                t.setDaemon(True)
                t.start()
            for ip in ips:
                self.q.put(ip)

            self.q.join()

        else:
            self.ping_list = ips

        if len(self.ping_list) == 0:
            print "not find any live machine - -|||"
            sys.exit()

        print "[*] Scanning for live machines done,it has Elapsed time:%s " % (time.time() - starttime)

    def prep_signs(self):
        """
        文件中获取
        :return:
        """
        sign_list = []
        for item in self.signs_from_file:
            (label, pattern) = item.split('|', 2)
            sign = (label, pattern)
            sign_list.append(sign)
        return sign_list

    @staticmethod
    def match_banner(banner, slist):
        """
        匹配端口对应服务类型
        :param banner:
        :param slist:
        :return:
        """
        # print banner
        for item in slist:
            p = re.compile(item[1])
            # print item[1]
            if p.search(banner):
                return item[0]
        return 'Unknown'

    def scan_ports(self):
        """
        扫端口及其对应服务类型函数
        :return:
        """
        while True:
            ip, port = self.sp.get()
            # print ip,port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 判断端口的服务类型
            service = 'Unknown'
            try:
                s.connect((ip, port))
            except:
                self.sp.task_done()
                continue

            try:
                result = s.recv(256)
                service = self.match_banner(result, self.signs)
            except:
                for probe in self.probes:
                    # print probe
                    try:
                        s.close()
                        sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sd.settimeout(5)
                        sd.connect((ip, port))
                        sd.send(probe)
                    except:
                        continue
                    try:
                        result = sd.recv(256)
                        service = self.match_banner(result, self.signs)
                        if service != 'Unknown':
                            break
                    except:
                        continue

            if service not in self.ip_dict:
                self.ip_dict[service] = []
                self.ip_dict[service].append(ip + ':' + str(port))
                self.lock.acquire()
                printRed("%s opening %s\r\n" % (ip, port))
                self.lock.release()
            else:
                self.ip_dict[service].append(ip + ':' + str(port))
                self.lock.acquire()
                printRed("%s opening %s\r\n" % (ip, port))
                self.lock.release()

            self.sp.task_done()

    def ports_scan(self, threads, filename):
        """
        端口扫描主函数
        :param threads:
        :param filename:
        :return:
        """
        print "Scanning ports now..."
        print "[*] start Scanning live machines' ports at %s" % time.ctime()
        starttime = time.time()

        for i in xrange(threads):
            st = Thread(target=self.scan_ports)
            st.setDaemon(True)
            st.start()

        for scanip in self.ping_list:
            for port in self.ports:
                self.sp.put((scanip, port))
        self.sp.join()
        print "[*] Scanning ports done,it has Elapsed time:%s " % (time.time() - starttime)
        # 将服务端口 信息 记录文件
        for name in self.ip_dict.keys():
            if len(self.ip_dict[name]):
                contents = str(name) + ' service has:\n' + '       ' + str(self.ip_dict[name]) + '\n'
                self.config.write_file(contents=contents, filename=filename)

    def handle_unknown(self):
        """
        处理没有识别的服务
        :return:
        """
        if 'Unknown' in self.ip_dict:
            for ip in self.ip_dict['Unknown']:
                # print ip
                try:
                    if str(ip).split(':')[1] == '389':
                        if "ldap" in self.ip_dict:
                            self.ip_dict['ldap'].append(ip)
                        else:
                            self.ip_dict['ldap'] = [ip]
                    if str(ip).split(':')[1] == '445':
                        if 'smb' in self.ip_dict:
                            self.ip_dict['smb'].append(ip)
                        else:
                            self.ip_dict['smb'] = [ip]
                    if str(ip).split(':')[1] in ['3306', '3307', '3308', '3309']:
                        if 'mysql' in self.ip_dict:
                            self.ip_dict['mysql'].append(ip)
                        else:
                            self.ip_dict['mysql'] = [ip]
                    if str(ip).split(':')[1] == '1433':
                        if 'mssql' in self.ip_dict:
                            self.ip_dict['mssql'].append(ip)
                        else:
                            self.ip_dict['mssql'] = [ip]
                    if str(ip).split(':')[1] in ['10022', '22']:
                        if 'ssh' in self.ip_dict:
                            self.ip_dict['ssh'].append(ip)
                        else:
                            self.ip_dict['ssh'] = [ip]
                    if str(ip).split(':')[1] == '27017':
                        if 'mongodb' in self.ip_dict:
                            self.ip_dict['mongodb'].append(ip)
                        else:
                            self.ip_dict['mongodb'] = [ip]
                    if str(ip).split(':')[1] == '5432':
                        if 'postgres' in self.ip_dict:
                            self.ip_dict['postgres'].append(ip)
                        else:
                            self.ip_dict['postgres'] = [ip]
                    if str(ip).split(':')[1] == '443':
                        if 'ssl' in self.ip_dict:
                            self.ip_dict['ssl'].append(ip)
                        else:
                            self.ip_dict['ssl'] = [ip]
                    if str(ip).split(':')[1] == '873':
                        if 'rsync' in self.ip_dict:
                            self.ip_dict['rsync'].append(ip)
                        else:
                            self.ip_dict['rsync'] = [ip]
                    if str(ip).split(':')[1] == '6379':
                        if 'redis' in self.ip_dict:
                            self.ip_dict['redis'].append(ip)
                        else:
                            self.ip_dict['redis'] = [ip]
                except Exception as e:
                    print e
                    # 处理被识别为http的mongo
            if "http" in self.ip_dict:
                for ip in self.ip_dict['http']:
                    if str(ip).split(':')[1] == '27017':
                        self.ip_dict['http'].remove(ip)
                        self.ip_dict['mongodb'].append(ip)

    def run(self, is_ping, threads, ips, filename):
        """
        主函数
        :param is_ping:
        :param threads:
        :param ips:
        :param filename:
        :return:
        """
        self.ping_scan(is_ping, threads, ips)
        self.ports_scan(threads, filename)
        self.handle_unknown()

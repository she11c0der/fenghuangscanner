#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan Config
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
import re
import os
import sys
from IPy import IP
from comm.printers import printRed


class Config(object):
    """
    一些配置处理
    """
    @staticmethod
    def get_ips(ip):
        """
        获取ip
        :param ip:
        :return:
        """
        ip_list = []
        try:
            if "-" in ip.split(".")[3]:
                start_num = int(ip.split(".")[3].split("-")[0])
                end_num = int(ip.split(".")[3].split("-")[1])
                for i in range(start_num, end_num):
                    ip_list.append("%s.%s.%s.%s" % (ip.split(".")[0], ip.split(".")[1], ip.split(".")[2], i))
            else:
                ips = IP(ip)
                for i in ips:
                    ip_list.append(str(i))
            return ip_list
        except:
            printRed("[!] not a valid ip given. you should put ip like 192.168.1.0/24, 192.168.0.0/16,192.168.0.1-200")
            sys.exit(0)

    @staticmethod
    def file2list(filename):
        """
        配置文件转文件明
        :param filename:
        :return:
        """
        ip_list = []
        try:
            fh = open(filename)
            for ip in fh.readlines():
                ip = ip.strip()
                ip_list.append(ip)
            fh.close()
            return ip_list
        except Exception, e:
            sys.exit(str(e))

    @staticmethod
    def write_file(filename, contents):
        """
        写文件
        :param filename:
        :param contents:
        :return:
        """
        f2 = open(filename, 'a+')
        f2.write(contents)
        f2.close()

    @staticmethod
    def fuzzy_finder(pocs_path):
        '''
        加载插件
        :param pocs_path:
        :return:
        '''
        suggestions = []
        files = os.listdir(pocs_path)
        pattern = '.*?\.py$'
        regex = re.compile(pattern)
        for item in files:
            match = regex.search(item)
            if match and item != '__init__.py':
                suggestions.append((len(match.group()), match.start(), pocs_path + '/' + item))
        return [x for _, _, x in sorted(suggestions)]

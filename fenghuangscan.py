#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan main
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""

import argparse
# import imp
import sys
from factorys.plugin_factory import PluginFactory
from comm.portscan import PortScan
from comm.config import Config

# 实例化config类
c = Config()

if __name__ == '__main__':
    # 接受cmd参数
    parser = argparse.ArgumentParser(
        description='ports&*weak password scanner. teams:xdsec.  author: ****** . Unauthorized test not allowed!!!')
    parser.add_argument('--ip', action="store", required=False, dest="ip", type=str,
                        help='ip like 192.168.1.0/24 or 192.168.0.0/16')
    parser.add_argument("--threads", action="store", required=False, dest="threads", type=int, default=50,
                        help='Maximum threads, default 50')
    parser.add_argument("--P", action="store", required=False, dest="isping", type=str, default='yes',
                        help='--P not mean no ping frist,default yes')
    parser.add_argument("--p", action="store", required=False, dest="user_ports", type=str, default='',
                        help='--p scan ports;like 21,80,445 or 22-1000')
    parser.add_argument("--file", action="store", required=False, dest="file", type=str,
                        help='get ips or domains for this file')

    args = parser.parse_args()
    ip = args.ip
    filename = args.file
    ips = []
    result_file = ""
    # 获取ip列表
    if ip:
        ips = c.get_ips(ip)
        result_file = "result/%s.txt" % args.ip.replace("/", "")
    elif filename:
        ips = c.file2list(filename)
        filename = filename.split("/")[-1]
        result_file = "result/%s.txt" % filename
    else:
        sys.exit("error args")

    is_ping = args.isping
    user_posts = args.user_ports
    threads = args.threads

    # 端口扫描
    p = PortScan(c, user_posts)
    p.run(is_ping, threads, ips, result_file)

    # 主机安全插件扫描
    plugins = PluginFactory(c)
    for plugin_name in plugins.pluginList:
        if plugin_name:
            plugin_name.run(p.ip_dict, threads, result_file)

    # # 插件扫描 这样做 pyinstaller编译有问题。。。
    # list_class = c.fuzzy_finder("./plugins")
    #
    # for i in list_class:
    #     poc = imp.load_source('pluginsscan', i)
    #     exp = poc.MyPoc(c)
    #     exp.run(p.ip_dict, threads, result_file)

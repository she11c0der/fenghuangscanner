#!/bin/env python
# -*- encoding:utf-8 -*-
"""
    fenghuangscan PluginFactory类
    ~~~~~~~~~~~~~~~~~~~~

    主函数
    :author = 'wilson'
"""
from plugins.ftp import MyPoc as FtpPoc
from plugins.smb import MyPoc as SmbPoc
from plugins.mysql import MyPoc as MysqlPoc
from plugins.mssql import MyPoc as MssqlPoc
from plugins.ldapd import MyPoc as LdapPoc
from plugins.mongodb import MyPoc as MongodbPoc
from plugins.redisexp import MyPoc as RedisPoc
from plugins.rsync import MyPoc as RsyncPoc
# from plugins.snmp import *
from plugins.ssh import MyPoc as SshPoc
from plugins.ssltest import MyPoc as SslPoc
from plugins.vnc import MyPoc as VncPoc
from plugins.web import MyPoc as WebPoc


def ftp_burp(c):
    t = FtpPoc(c)
    return t


def smb_burp(c):
    t = SmbPoc(c)
    return t


def mysql_burp(c):
    t = MysqlPoc(c)
    return t


def mssql_burp(c):
    t = MssqlPoc(c)
    return t


def ldap_burp(c):
    t = LdapPoc(c)
    return t


def mongodb_burp(c):
    t = MongodbPoc(c)
    return t


def redis_burp(c):
    t = RedisPoc(c)
    return t


def rsync_burp(c):
    t = RsyncPoc(c)
    return t


def ssh_burp(c):
    t = SshPoc(c)
    return t


def ssl_burp(c):
    t = SslPoc(c)
    return t


def vnc_burp(c):
    t = VncPoc(c)
    return t


def web_burp(c):
    t = WebPoc(c)
    return t


# 类
class PluginFactory(object):
    """
    工程类
    """

    def __init__(self, c):
        """
        初始化
        :param c:
        """
        self.pluginList = []
        self.config = c
        self.pluginCategory = {
            "ftp": ftp_burp,
            "smb": smb_burp,
            "mysql": mysql_burp,
            "mssql": mssql_burp,
            "ldap": ldap_burp,
            "mongodb": mongodb_burp,
            "redis": redis_burp,
            "rsync": rsync_burp,
            "ssh": ssh_burp,
            "ssl": ssl_burp,
            "vnc": vnc_burp,
            "web": web_burp,
        }
        self.get_plugin_list()

    def get_plugin_list(self):
        for name in self.pluginCategory:
            # 实例化每个类
            result_t = self.pluginCategory.get(name)(self.config)
            self.pluginList.append(result_t)

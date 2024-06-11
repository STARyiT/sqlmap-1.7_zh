#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "Oracle 操作系统命令执行功能不支持"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "Oracle 操作系统 shell 功能不支持"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "Oracle 操作系统出带控制功能不支持"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "Oracle 尚未实现一键操作系统外带控制功能"
        raise SqlmapUnsupportedFeatureException(errMsg)

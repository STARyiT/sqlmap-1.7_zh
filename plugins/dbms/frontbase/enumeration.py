#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = "在 FrontBase 上无法获取 banner"
        logger.warning(warnMsg)

        return None

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "在 FrontBase 上无法枚举用户权限"
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "在 FrontBase 上无法枚举主机名"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在 FrontBase 上无法枚举 SQL 语句"
        logger.warning(warnMsg)

        return []

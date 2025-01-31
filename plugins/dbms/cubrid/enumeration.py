#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "在 Cubrid 上无法枚举用户密码哈希值"
        logger.warning(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = "在 Cubrid 上无法枚举 SQL 语句"
        logger.warning(warnMsg)

        return []

    def getRoles(self, *args, **kwargs):
        warnMsg = "在 Cubrid 上无法枚举用户角色"
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "在 Cubrid 上无法枚举主机名"
        logger.warning(warnMsg)

#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import DERBY_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.DERBY)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web 服务器", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("后端 DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "后端 DBMS: "

        if not conf.extensiveFp:
            value += DBMS.DERBY
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "活跃指纹: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%sbanner 解析指纹: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml 错误消息指纹: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(DERBY_ALIASES):
            setDbms(DBMS.DERBY)

            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.DERBY
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM SYSIBM.SYSDUMMY1 {LIMIT 1 OFFSET 0})")

        if result:
            infoMsg = "确认 %s" % DBMS.DERBY
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("(SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1) IS NOT NULL")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.DERBY
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.DERBY)

            self.getBanner()

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.DERBY
            logger.warning(warnMsg)

            return False

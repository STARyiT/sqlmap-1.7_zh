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
from lib.core.settings import MIMERSQL_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MIMERSQL)

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
            value += DBMS.MIMERSQL
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
        if not conf.extensiveFp and Backend.isDbmsWithin(MIMERSQL_ALIASES):
            setDbms(DBMS.MIMERSQL)

            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.MIMERSQL
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("IRAND()>=0")

        if result:
            infoMsg = "确认 %s" % DBMS.MIMERSQL
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("PASTE('[RANDSTR1]',0,0,'[RANDSTR2]')='[RANDSTR2][RANDSTR1]'")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.MIMERSQL
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.MIMERSQL)

            self.getBanner()

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.MIMERSQL
            logger.warning(warnMsg)

            return False

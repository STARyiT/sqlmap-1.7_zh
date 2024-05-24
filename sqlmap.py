#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

try:
    import sys

    sys.dont_write_bytecode = True

    try:
        __import__("lib.utils.versioncheck")  # this has to be the first non-standard import
    except ImportError:
        sys.exit(
            "[!] 检测到sqlmap安装错误 (缺少模块)。 详细信息访问: 'https://github.com/sqlmapproject/sqlmap/#installation' ")

    import bdb
    import glob
    import inspect
    import json
    import logging
    import os
    import re
    import shutil
    import sys
    import tempfile
    import threading
    import time
    import traceback
    import warnings

    if "--deprecations" not in sys.argv:
        warnings.filterwarnings(action="ignore", category=DeprecationWarning)
    else:
        warnings.resetwarnings()
        warnings.filterwarnings(action="ignore", message="'crypt'", category=DeprecationWarning)
        warnings.simplefilter("ignore", category=ImportWarning)
        if sys.version_info >= (3, 0):
            warnings.simplefilter("ignore", category=ResourceWarning)

    warnings.filterwarnings(action="ignore", message="该版本不再支持Python2，请使用Python3. ")
    warnings.filterwarnings(action="ignore", message=".*已输入 ", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*使用了较旧的模块或版本 ", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*将使用默认的缓冲区大小 ", category=RuntimeWarning)
    warnings.filterwarnings(action="ignore", category=UserWarning, module="psycopg2")

    from lib.core.data import logger

    from lib.core.common import banner
    from lib.core.common import checkIntegrity
    from lib.core.common import checkPipedInput
    from lib.core.common import createGithubIssue
    from lib.core.common import dataToStdout
    from lib.core.common import extractRegexResult
    from lib.core.common import filterNone
    from lib.core.common import getDaysFromLastUpdate
    from lib.core.common import getFileItems
    from lib.core.common import getSafeExString
    from lib.core.common import maskSensitiveData
    from lib.core.common import openFile
    from lib.core.common import setPaths
    from lib.core.common import weAreFrozen
    from lib.core.convert import getUnicode
    from lib.core.common import MKSTEMP_PREFIX
    from lib.core.common import setColor
    from lib.core.common import unhandledExceptionMessage
    from lib.core.compat import LooseVersion
    from lib.core.compat import xrange
    from lib.core.data import cmdLineOptions
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.datatype import OrderedSet
    from lib.core.exception import SqlmapBaseException
    from lib.core.exception import SqlmapShellQuitException
    from lib.core.exception import SqlmapSilentQuitException
    from lib.core.exception import SqlmapUserQuitException
    from lib.core.option import init
    from lib.core.option import initOptions
    from lib.core.patch import dirtyPatches
    from lib.core.patch import resolveCrossReferences
    from lib.core.settings import GIT_PAGE
    from lib.core.settings import IS_WIN
    from lib.core.settings import LAST_UPDATE_NAGGING_DAYS
    from lib.core.settings import LEGAL_DISCLAIMER
    from lib.core.settings import THREAD_FINALIZATION_TIMEOUT
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import VERSION
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.crawler import crawl
except KeyboardInterrupt:
    errMsg = "user aborted"

    if "logger" in globals():
        logger.critical(errMsg)
        raise SystemExit
    else:
        import time

        sys.exit("\r[%s] [关键] %s" % (time.strftime("%X"), errMsg))


def modulePath():
    """
    即使我们被冻结，也能获得程序的目录
    使用 py2exe
    """

    try:
        _ = sys.executable if weAreFrozen() else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return getUnicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)


def checkEnvironment():
    try:
        os.path.isdir(modulePath())
    except UnicodeEncodeError:
        errMsg = "您的系统无法正确处理非ASCII路径. "
        errMsg += "请将sqlmap的目录移动到其他位置. "
        logger.critical(errMsg)
        raise SystemExit

    if LooseVersion(VERSION) < LooseVersion("1.0"):
        errMsg = "你的运行环境 (e.g. PYTHONPATH) 是 "
        errMsg += "错误的，请确保您没有运行.  "
        errMsg += "新版本的sqlmap与旧版本的运行脚本"
        errMsg += "版本"
        logger.critical(errMsg)
        raise SystemExit

    # Patch for pip (import) environment
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions", "conf", "kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)

        for _ in (
        "SqlmapBaseException", "SqlmapShellQuitException", "SqlmapSilentQuitException", "SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)


def main():
    """
    从命令行运行的时候sqlmap的主要功能
    """

    try:
        dirtyPatches()
        resolveCrossReferences()
        checkEnvironment()
        setPaths(modulePath())
        banner()

        # Store original command line options for possible later restoration
        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args, "__dict__") else args)
        initOptions(cmdLineOptions)

        if checkPipedInput():
            conf.batch = True

        if conf.get("api"):
            # heavy imports
            from lib.utils.api import StdDbOut
            from lib.utils.api import setRestAPILog

            # Overwrite system standard output and standard error to write
            # to an IPC database
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")

            setRestAPILog()

        conf.showTime = True
        dataToStdout("[!] 免责声明: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] 开始时间 @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        init()

        if not conf.updateAll:
            # Postponed imports (faster start)
            if conf.smokeTest:
                from lib.core.testing import smokeTest
                os._exitcode = 1 - (smokeTest() or 0)
            elif conf.vulnTest:
                from lib.core.testing import vulnTest
                os._exitcode = 1 - (vulnTest() or 0)
            else:
                from lib.controller.controller import start
                if conf.profile:
                    from lib.core.profiling import profile
                    globals()["start"] = start
                    profile()
                else:
                    try:
                        if conf.crawlDepth and conf.bulkFile:
                            targets = getFileItems(conf.bulkFile)

                            for i in xrange(len(targets)):
                                target = None

                                try:
                                    kb.targets = OrderedSet()
                                    target = targets[i]

                                    if not re.search(r"(?i)\Ahttp[s]*://", target):
                                        target = "http://%s" % target

                                    infoMsg = "开始爬取目标URL: '%s' (%d/%d)" % (target, i + 1, len(targets))
                                    logger.info(infoMsg)

                                    crawl(target)
                                except Exception as ex:
                                    if target and not isinstance(ex, SqlmapUserQuitException):
                                        errMsg = "爬取目标出现问题: '%s' ('%s')" % (target, getSafeExString(ex))
                                        logger.error(errMsg)
                                    else:
                                        raise
                                else:
                                    if kb.targets:
                                        start()
                        else:
                            start()
                    except Exception as ex:
                        os._exitcode = 1

                        if "无法启动新主题" in getSafeExString(ex):
                            errMsg = "无法启动新线程，请检查操作系统的线程限制"
                            logger.critical(errMsg)
                            raise SystemExit
                        else:
                            raise

    except SqlmapUserQuitException:
        if not conf.batch:
            errMsg = "用户退出"
            logger.error(errMsg)

    except (SqlmapSilentQuitException, bdb.BdbQuit):
        pass

    except SqlmapShellQuitException:
        cmdLineOptions.sqlmapShell = False

    except SqlmapBaseException as ex:
        errMsg = getSafeExString(ex)
        logger.critical(errMsg)

        os._exitcode = 1

        raise SystemExit

    except KeyboardInterrupt:
        try:
            print()
        except IOError:
            pass

    except EOFError:
        print()

        errMsg = "退出"
        logger.error(errMsg)

    except SystemExit as ex:
        os._exitcode = ex.code or 0

    except:
        print()
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()
        valid = checkIntegrity()

        os._exitcode = 255

        if any(_ in excMsg for _ in ("内存错误", "无法分配内存")):
            errMsg = "检测到内容耗尽"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("没有剩余空间", "超过磁盘配额", "访问时磁盘空间已满")):
            errMsg = "输出设备满，无多余存储空间"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("分页文件太小",)):
            errMsg = "分页文件无剩余空间"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("拒接访问", "子进程", "metasploit")):
            errMsg = "运行Metasploit时发生权限错误"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("拒接访问", "metasploit")):
            errMsg = "运行Metasploit时发生权限错误"
            logger.critical(errMsg)
            raise SystemExit

        elif "只读文件系统" in excMsg:
            errMsg = "输出设备权限为只读"
            logger.critical(errMsg)
            raise SystemExit

        elif "系统资源不足" in excMsg:
            errMsg = "检测到资源耗尽"
            logger.critical(errMsg)
            raise SystemExit

        elif "操作错误：磁盘 I/O 错误" in excMsg:
            errMsg = "输出设备 I/O 出错"
            logger.critical(errMsg)
            raise SystemExit

        elif "Violation of BIDI" in excMsg:
            errMsg = "invalid URL (violation of Bidi IDNA rule - RFC 5893)"
            logger.critical(errMsg)
            raise SystemExit

        elif "无效IPv6的URL" in excMsg:
            errMsg = "无效的URL ('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif "_mkstemp_inner" in excMsg:
            errMsg = "访问临时文件时出现问题"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("tempfile.mkdtemp", "tempfile.mkstemp", "tempfile.py")):
            errMsg = "无法写入临时目录 '%s'. " % tempfile.gettempdir()
            errMsg += "请确保磁盘未满，并且"
            errMsg += "有足够的写入权限"
            errMsg += "创建临时文件和/或目录"
            logger.critical(errMsg)
            raise SystemExit

        elif "拒接许可: '" in excMsg:
            match = re.search(r"拒接许可: '([^']*)", excMsg)
            errMsg = "访问文件时发生权限错误 '%s'" % match.group(1)
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("twophase", "sqlalchemy")):
            errMsg = "请更新 'sqlalchemy' 软件包（>= 1.1.11）"
            errMsg += "(参考: 'https://qiita.com/tkprof/items/7d7b2d00df9c5f16fffe')"
            logger.critical(errMsg)
            raise SystemExit

        elif "传递给 PyUnicode_New 的最大字符无效" in excMsg and re.search(r"\A3\.[34]", sys.version) is not None:
            errMsg = "请更新Python3版本 (>= 3.5) "
            errMsg += "(参考: 'https://bugs.python.org/issue18183')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("scramble_caching_sha2", "TypeError")):
            errMsg = "请降级 'PyMySQL' 软件包 (=< 0.8.1) "
            errMsg += "(参考: 'https://github.com/PyMySQL/PyMySQL/issues/700')"
            logger.critical(errMsg)
            raise SystemExit

        elif "必须是固定的缓冲区，而不是字节数组" in excMsg:
            errMsg = "在Python解释器中发生了错误，该解释器"
            errMsg += "已在2.7中修复。请相应更新 "
            errMsg += "(参考: 'https://bugs.python.org/issue8104')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("OSError： [Errno 22] 参数无效：'", "importlib")):
            errMsg = "无法读取文件 '%s'" % extractRegexResult(r"OSError: \[Errno 22\] 无效参数: '(?P<result>[^']+)",
                                                              excMsg)
            logger.critical(errMsg)
            raise SystemExit

        elif "hash_randomization" in excMsg:
            errMsg = "在 Python 解释器中发生了错误，该解释器"
            errMsg += "已在 2.7.3 中修复。请相应更新"
            errMsg += "(参考: 'https://docs.python.org/2/library/sys.html')"
            logger.critical(errMsg)
            raise SystemExit

        elif "属性错误：无法访问项目" in excMsg and re.search(r"3\.11\.\d+a", sys.version):
            errMsg = "在使用Python3.11的ALPHA版本运行sqlmap时，存在一个已知问题"
            errMsg += "请降级到某个稳定的Python版本"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("资源暂不可用", "os.fork()", "dictionaryAttack")):
            errMsg = "运行多进程哈希破解时出现问题"
            errMsg += "请使用以下选项重新运行 '--threads=1'"
            logger.critical(errMsg)
            raise SystemExit

        elif "无法启动新主题" in excMsg:
            errMsg = "在创建新线程实例时出现了问题"
            errMsg += "请确保没有运行过多进程"
            if not IS_WIN:
                errMsg += " (or increase the 'ulimit -u' value)"
            logger.critical(errMsg)
            raise SystemExit

        elif "无法配置全局读锁定" in excMsg:
            errMsg = "常规读锁定配置失败"
            errMsg += "('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("pymysql", "configparser")):
            errMsg = "检测到错误的pymsql初始化（使用Python3依赖项）"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("ntlm", "socket.error, err", "SyntaxError")):
            errMsg = "检测到错误的python-ntlm初始化（使用Python2语法）"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("drda", "to_bytes")):
            errMsg = "检测到错误的'drda'初始化（使用Python3语法）"
            logger.critical(errMsg)
            raise SystemExit

        elif "'WebSocket' 对象无属性 'status'" in excMsg:
            errMsg = "检测到错误的websocket库"
            errMsg += " (参考: 'https://github.com/sqlmapproject/sqlmap/issues/4572#issuecomment-775041086')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("window = tkinter.Tk()",)):
            errMsg = "图形用户界面初始化出现问题"
            errMsg += "('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("无法访问项目 'liveTest'",)):
            errMsg = "检测到使用不同版本sqlmap的文件"
            logger.critical(errMsg)
            raise SystemExit

        elif kb.get("dumpKeyboardInterrupt"):
            raise SystemExit

        elif any(_ in excMsg for _ in ("Broken pipe",)):
            raise SystemExit

        elif valid is False:
            errMsg = "代码完整性检查失败（关闭自动创建问题）"
            errMsg += "您应该从官方GitHub获取最新的开发版本"
            errMsg += "repository at '%s'" % GIT_PAGE
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in "%s\n%s" % (errMsg, excMsg) for _ in ("tamper/", "waf/", "--engagement-dojo")):
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in (
        "ImportError", "ModuleNotFoundError", "<frozen", "Can't find file for module", "SAXReaderNotAvailable",
        "source code string cannot contain null bytes", "No module named", "tp_name field",
        "module 'sqlite3' has no attribute 'OperationalError'")):
            errMsg = "运行环境无效 ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("SyntaxError: Non-ASCII character", ".py on line", "but no encoding declared")):
            errMsg = "invalid runtime environment ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("权限错误: [WinError 5]", "multiprocessing")):
            errMsg = "t在该系统上运行多进程存在权限问题"
            errMsg += "携带参数重新运行'--disable-multi'"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("无此文件", "_'")):
            errMsg = "检测到安装已损坏 ('%s'). " % excMsg.strip().split('\n')[-1]
            errMsg += "您应该从官方GitHub获取最新的开发版本 "
            errMsg += "repository at '%s'" % GIT_PAGE
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("无此文件", "sqlmap.conf", "Test")):
            errMsg = "您试图在生产环境中运行（隐藏的）开发测试"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("HTTPNtlmAuthHandler", "'str' object has no attribute 'decode'")):
            errMsg = "包 'python-ntlm' 存在兼容性问题"
            errMsg += "Python3 (Reference: 'https://github.com/mullender/python-ntlm/pull/61')"
            logger.critical(errMsg)
            raise SystemExit

        elif "'DictObject' 对象无属性 '" in excMsg and all(_ in errMsg for _ in ("(fingerprinted)", "(identified)")):
            errMsg = "存在错误的指纹"
            errMsg += "存在错误的特征识别几率很大"
            errMsg += "建议携带参数 '--flush-session'"
            logger.critical(errMsg)
            raise SystemExit

        elif "数据库磁盘镜像存在异常" in excMsg:
            errMsg = "本地会话文件似乎存在异常。请携带参数 '--flush-session'"
            logger.critical(errMsg)
            raise SystemExit

        elif "属性错误：'模块' 对象没有属性'F_GETFD'" in excMsg:
            errMsg = "运行时无效 (\"%s\") " % excMsg.split("Error: ")[-1].strip()
            errMsg += "(参考: 'https://stackoverflow.com/a/38841364' & 'https://bugs.python.org/issue24944#msg249231')"
            logger.critical(errMsg)
            raise SystemExit

        elif "错误的元数据（未知类型代码）" in excMsg:
            match = re.search(r"\s*(.+)\s+ValueError", excMsg)
            errMsg = "你的某个 .pyc 已被损坏 %s" % (" ('%s')" % match.group(1) if match else "")
            errMsg += "请删除系统中的 .pyc 文件，以解决问题。"
            logger.critical(errMsg)
            raise SystemExit

        for match in re.finditer(r'File "(.+?)", line', excMsg):
            file_ = match.group(1)
            try:
                file_ = os.path.relpath(file_, os.path.dirname(__file__))
            except ValueError:
                pass
            file_ = file_.replace("\\", '/')
            if "../" in file_:
                file_ = re.sub(r"(\.\./)+", '/', file_)
            else:
                file_ = file_.lstrip('/')
            file_ = re.sub(r"/{2,}", '/', file_)
            excMsg = excMsg.replace(match.group(1), file_)

        errMsg = maskSensitiveData(errMsg)
        excMsg = maskSensitiveData(excMsg)

        if conf.get("api") or not valid:
            logger.critical("%s\n%s" % (errMsg, excMsg))
        else:
            logger.critical(errMsg)
            dataToStdout("%s\n" % setColor(excMsg.strip(), level=logging.CRITICAL))
            createGithubIssue(errMsg, excMsg)

    finally:
        kb.threadContinue = False

        if getDaysFromLastUpdate() > LAST_UPDATE_NAGGING_DAYS:
            warnMsg = "你的sqlmap版本已经过期，请及时更新"
            logger.warning(warnMsg)

        if conf.get("showTime"):
            dataToStdout("\n[*] ending @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        kb.threadException = True

        if kb.get("tempDir"):
            for prefix in (
            MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING, MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                for filepath in glob.glob(os.path.join(kb.tempDir, "%s*" % prefix)):
                    try:
                        os.remove(filepath)
                    except OSError:
                        pass

            if not filterNone(filepath for filepath in glob.glob(os.path.join(kb.tempDir, '*')) if not any(
                    filepath.endswith(_) for _ in (".lock", ".exe", ".so", '_'))):  # ignore junk files
                try:
                    shutil.rmtree(kb.tempDir, ignore_errors=True)
                except OSError:
                    pass

        if conf.get("hashDB"):
            conf.hashDB.flush(True)
            conf.hashDB.close()  # NOTE: because of PyPy

        if conf.get("harFile"):
            try:
                with openFile(conf.harFile, "w+b") as f:
                    json.dump(conf.httpCollector.obtain(), fp=f, indent=4, separators=(',', ': '))
            except SqlmapBaseException as ex:
                errMsg = getSafeExString(ex)
                logger.critical(errMsg)

        if conf.get("api"):
            conf.databaseCursor.disconnect()

        if conf.get("dumper"):
            conf.dumper.flush()

        # short delay for thread finalization
        _ = time.time()
        while threading.active_count() > 1 and (time.time() - _) > THREAD_FINALIZATION_TIMEOUT:
            time.sleep(0.01)

        if cmdLineOptions.get("sqlmapShell"):
            cmdLineOptions.clear()
            conf.clear()
            kb.clear()
            conf.disableBanner = True
            main()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except:
        traceback.print_exc()
    finally:
        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if threading.active_count() > 1:
            os._exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))
else:
    # cancelling postponed imports (because of CI/CD checks)
    __import__("lib.controller.controller")

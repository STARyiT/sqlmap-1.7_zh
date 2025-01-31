#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import readInput
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import OrderedSet
from lib.core.exception import SqlmapSyntaxException
from lib.request.connect import Connect as Request
from thirdparty.six.moves import http_client as _http_client

abortedFlag = None

def parseSitemap(url, retVal=None):
    global abortedFlag

    if retVal is not None:
        logger.debug("解析站点地图 '%s'" % url)

    try:
        if retVal is None:
            abortedFlag = False
            retVal = OrderedSet()

        try:
            content = Request.getPage(url=url, raise404=True)[0] if not abortedFlag else ""
        except _http_client.InvalidURL:
            errMsg = "提供的站点地图URL无效('%s')" % url
            raise SqlmapSyntaxException(errMsg)

        for match in re.finditer(r"<loc>\s*([^<]+)", content or ""):
            if abortedFlag:
                break
            url = match.group(1).strip()
            if url.endswith(".xml") and "sitemap" in url.lower():
                if kb.followSitemapRecursion is None:
                    message = "检测到网站地图递归。你想要跟随吗？[y/N] "
                    kb.followSitemapRecursion = readInput(message, default='N', boolean=True)
                if kb.followSitemapRecursion:
                    parseSitemap(url, retVal)
            else:
                retVal.add(url)

    except KeyboardInterrupt:
        abortedFlag = True
        warnMsg = "用户在站点地图解析过程中中止。sqlmap将使用部分列表"
        logger.warning(warnMsg)

    return retVal

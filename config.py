# Configuration file
# You can customize some configuration here.

# Database settings
# type > dict
DB_CONFIG = {
    'DB_TYPE': 'mysql',
    'DB_HOST': '127.0.0.1',
    'DB_PORT': '3306',
    'DB_USER': 'root',
    'DB_PASS': 'yuge',
    'DB_CHARSET': 'utf8',
    'DB_DATABASE': 'Net_Analyzer',
    'DB_FILE': './db.sqlite3'
}

response_header_key = ['ext', 'content-type', 'connection', 'date', 'server', 'expires',
                      'cache-control', 'last-modified', 'set-cookie', 'accept-ranges', 'mime-version',
                      'etag', 'x-powered-by', 'transfer-encoding', 'age', 'vary', 'pragma', 'www-authenticate',
                      'location', 'x-frame-options', 'x-cache', 'content-language', 'via', 'x-ua-compatible',
                      'p3p', 'content-location', 'x-aspnet-version', 'link', 'x-pingback', 'cf-ray',
                      'access-control-allow-origin', 'access-control-allow-headers', 'access-control-allow-methods',
                      'ratelimit-limit', 'x-alert', 'access-control-allow-credentials', 'retry-after', 'x-via',
                      'keep-alive', 'timing-allow-origin']

request_header_key = []

MODEL_PATH = 'E:/roger/models/'

FEATRUE_TYPE = {
    'ua_banner': 'ua_banner',
    'response_banner': 'response_banner',
    'web_fingerprint': 'web_fingerprint',
    'tcpip_fingerprint': 'tcpip_fingerprint'
}

OS_NAME = ['AIX', 'Linux', 'Ubuntu', 'FreeBSD', 'NetBSD',
           'NetBSD', 'OpenBSD', 'OpenBSD', 'Solaris',
           'SunOS', 'IRIX', 'Tru64', 'OpenVMS', 'MacOS',
           'Windows', 'Windows', 'HP-UX', 'RISC OS',
           'BSD/OS', 'NewtonOS', 'NeXTSTEP', 'BeOS',
           'OS/400', 'OS/390', 'ULTRIX', 'QNX', 'Novell',
           'SCO', 'DOS', 'OS/2', 'TOPS-20', 'AMIGA', 'Plan9',
           'AMIGAOS', 'FreeMiNT', 'Checkpoint', 'ExtremeWare',
           'Nokia', 'FortiNet', 'Eagle', 'Cisco', 'Alteon',
           'Nortel', 'Google', 'NetCache', 'CacheFlow', 'Dell',
           'Inktomi', 'LookSmart', 'Proxyblocker', 'Redline',
           'PalmOS', 'SymbianOS', 'Zaurus', 'PocketPC',
           'Contiki', 'Sega', 'Sony', 'AXIS', 'NMAP', 'NAST',
           'p0f', 'Mysterious', 'Mysterious', 'Windows', 'Android',
           'Mac OS X', 'unix','Windows Phone', 'Windows CE',
           'Mac OS X', 'Debian', 'Fedora', 'iOS', 'QNX', 'GNU OS',
           'Darwin', 'Firefox OS', 'Chrome OS', 'BlackBerry', 'Bada',
           'FreeBSD', 'AIX', 'SUSE', 'Syllable', 'OpenBSD', 'Mint',
           'Gentoo', 'Windows', 'Solaris', 'Tizen', 'Mandriva',
           'OS/2', 'NetBSD', 'Red Hat', 'BeOS', 'Windows Xbox',
           'XrossMediaBar', 'AROS', 'IRIX', 'Brew', 'Symbian', 'HP-UX',
           'CentOS', 'Sailfish', 'OS/2 Warp', 'MeeGo', 'webOS', 'Arch Linux',
           'Nintento DS', 'Mac OS', 'LiveArea', 'MINIX', 'BlackBerry Tablet', 'Haiku OS' ]
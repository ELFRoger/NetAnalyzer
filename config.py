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

respose_header_key = ['ext', 'content-type', 'connection', 'date', 'server', 'expires',
                      'cache-control', 'last-modified', 'set-cookie', 'accept-ranges', 'mime-version',
                      'etag', 'x-powered-by', 'transfer-encoding', 'age', 'vary', 'pragma', 'www-authenticate',
                      'location', 'x-frame-options', 'x-cache', 'content-language', 'via', 'x-ua-compatible',
                      'p3p', 'content-location', 'x-aspnet-version', 'link', 'x-pingback', 'cf-ray',
                      'access-control-allow-origin', 'access-control-allow-headers', 'access-control-allow-methods',
                      'ratelimit-limit', 'x-alert', 'access-control-allow-credentials', 'retry-after', 'x-via',
                      'keep-alive', 'timing-allow-origin', 'content-length']

request_header_key = []

MODEL_PATH = '../models/'
import pymysql
import config
import libs.common


def db_cursor_init():
    db_host = config.DB_CONFIG['DB_HOST']
    db_user = config.DB_CONFIG['DB_USER']
    db_pass = config.DB_CONFIG['DB_PASS']
    db_database = config.DB_CONFIG['DB_DATABASE']
    db_conn = pymysql.connect(db_host, db_user, db_pass, db_database, charset='utf8')
    db_cursor = db_conn.cursor()

    libs.common.set_value('db_cursor', db_cursor)
    libs.common.set_value('db_conn', db_conn)
    return True


def db_close():
    conn = libs.common.get_value('db_conn')
    conn.close()
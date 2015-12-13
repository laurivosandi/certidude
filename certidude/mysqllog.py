
import logging
import time
 
class MySQLLogHandler(logging.Handler):
 
    SQL_CREATE_TABLE = """CREATE TABLE IF NOT EXISTS log(
        created datetime, facility varchar(30), level int,
        severity varchar(10), message text, module varchar(20),
        func varchar(20), lineno int, exception text, process int,
        thread text, thread_name text)"""
 
    SQL_INSERT_ENTRY = """insert into log( created, facility, level, severity,
        message, module, func, lineno, exception, process, thread,
        thread_name) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
 
    def __init__(self, pool):
        logging.Handler.__init__(self)
        self.pool = pool
        conn = self.pool.get_connection()
        cur = conn.cursor()
        cur.execute(self.SQL_CREATE_TABLE)
        conn.commit()
        cur.close()
        conn.close()
 
    def emit(self, record):
        conn = self.pool.get_connection()
        cur = conn.cursor()
        cur.execute(self.SQL_INSERT_ENTRY, (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created)),
            record.name,
            record.levelno,
            record.levelname.lower(),
            record.msg % record.args, record.module,
            record.funcName,
            record.lineno,
            logging._defaultFormatter.formatException(record.exc_info) if record.exc_info else "",
            record.process,
            record.thread,
            record.threadName))
        conn.commit()
        cur.close()
        conn.close()

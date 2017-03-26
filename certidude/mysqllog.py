
import logging
import time
from datetime import datetime
from certidude.relational import RelationalMixin
 
class LogHandler(logging.Handler, RelationalMixin):
    SQL_CREATE_TABLES = "log_tables.sql"
 
    def __init__(self, uri):
        logging.Handler.__init__(self)
        RelationalMixin.__init__(self, uri)

    def emit(self, record):
        self.sql_execute("log_insert_entry.sql",
            datetime.utcfromtimestamp(record.created),
            record.name,
            record.levelno,
            record.levelname.lower(),
            record.msg % record.args, record.module,
            record.funcName,
            record.lineno,
            logging._defaultFormatter.formatException(record.exc_info) if record.exc_info else "",
            record.process,
            record.thread,
            record.threadName)

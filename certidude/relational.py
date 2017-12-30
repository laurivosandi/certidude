

import click
import re
import os
from urllib.parse import urlparse

SCRIPTS = {}

class RelationalMixin(object):
    """
    Thin wrapper around SQLite and MySQL database connectors
    """

    SQL_CREATE_TABLES = ""

    def __init__(self, uri):
        self.uri = urlparse(uri)

    def sql_connect(self):
        if self.uri.scheme == "mysql":
            import mysql.connector
            conn = mysql.connector.connect(
                user=self.uri.username,
                password=self.uri.password,
                host=self.uri.hostname,
                database=self.uri.path[1:])
        elif self.uri.scheme == "sqlite":
            if self.uri.netloc:
                raise ValueError("Malformed database URI %s" % self.uri)
            import sqlite3
            conn = sqlite3.connect(self.uri.path)
        else:
            raise NotImplementedError("Unsupported database scheme %s, currently only mysql://user:pass@host/database or sqlite:///path/to/database.sqlite is supported" % o.scheme)

        if self.SQL_CREATE_TABLES and self.SQL_CREATE_TABLES not in SCRIPTS:
            cur = conn.cursor()
            buf, path = self.sql_load(self.SQL_CREATE_TABLES)
            click.echo("Executing: %s" % path)
            if self.uri.scheme == "sqlite":
                cur.executescript(buf)
            else:
                cur.execute(buf, multi=True)
            conn.commit()
            cur.close()
        return conn

    def sql_resolve_script(self, filename):
        return os.path.realpath(os.path.join(os.path.dirname(__file__),
            "sql", self.uri.scheme, filename))


    def sql_load(self, filename):
        if filename in SCRIPTS:
            return SCRIPTS[filename]

        fh = open(self.sql_resolve_script(filename))
        click.echo("Caching SQL script: %s" % fh.name)
        buf = re.sub("\s*\n\s*", " ", fh.read())
        SCRIPTS[filename] = buf, fh.name
        fh.close()
        return buf, fh.name


    def sql_execute(self, script, *args):
        conn = self.sql_connect()
        cursor = conn.cursor()
        click.echo("Executing %s with %s" % (script, args))
        buf, path = self.sql_load(script)
        cursor.execute(buf, args)
        rowid = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        return rowid


    def iterfetch(self, query, *args):
        conn = self.sql_connect()
        cursor = conn.cursor()
        cursor.execute(query, args)
        cols = [j[0] for j in cursor.description]
        def g():
            for row in cursor:
                yield dict(zip(cols, row))
            cursor.close()
            conn.close()
        return tuple(g())

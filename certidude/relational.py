

import click
import re
import os
from urlparse import urlparse

SCRIPTS = {}

class RelationalMixin(object):
    """
    Thin wrapper around SQLite and MySQL database connectors
    """

    SQL_CREATE_TABLES = ""

    def __init__(self, uri):
        self.uri = urlparse(uri)
        if self.SQL_CREATE_TABLES and self.SQL_CREATE_TABLES not in SCRIPTS:
            conn = self.sql_connect()
            cur = conn.cursor()
            with open(self.sql_resolve_script(self.SQL_CREATE_TABLES)) as fh:
                click.echo("Executing: %s" % fh.name)
                if self.uri.scheme == "sqlite":
                    cur.executescript(fh.read())
                else:
                    cur.execute(fh.read())
            conn.commit()
            cur.close()
            conn.close()


    def sql_connect(self):
        if self.uri.scheme == "mysql":
            import mysql.connector
            return mysql.connector.connect(
                user=self.uri.username,
                password=self.uri.password,
                host=self.uri.hostname,
                database=self.uri.path[1:])
        elif self.uri.scheme == "sqlite":
            if self.uri.netloc:
                raise ValueError("Malformed database URI %s" % self.uri)
            import sqlite3
            return sqlite3.connect(self.uri.path)
        else:
            raise NotImplementedError("Unsupported database scheme %s, currently only mysql://user:pass@host/database or sqlite:///path/to/database.sqlite is supported" % o.scheme)


    def sql_resolve_script(self, filename):
        return os.path.realpath(os.path.join(os.path.dirname(__file__),
            "sql", self.uri.scheme, filename))


    def sql_load(self, filename):
        if filename in SCRIPTS:
            return SCRIPTS[filename]

        fh = open(self.sql_resolve_script(filename))
        click.echo("Caching SQL script: %s" % fh.name)
        buf = re.sub("\s*\n\s*", " ", fh.read())
        SCRIPTS[filename] = buf
        fh.close()
        return buf


    def sql_execute(self, script, *args):
        conn = self.sql_connect()
        cursor = conn.cursor()
        click.echo("Executing %s with %s" % (script, args))
        cursor.execute(self.sql_load(script), args)
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


    def sql_fetchone(self, query, *args):
        conn = self.sql_connect()
        cursor = conn.cursor()
        cursor.execute(query, args)
        cols = [j[0] for j in cursor.description]

        for row in cursor:
            r = dict(zip(cols, row))
            cursor.close()
            conn.close()
            return r
        return None


import string
from datetime import datetime, timedelta
from certidude import authority, config, mailer, const
from certidude.relational import RelationalMixin
from certidude.common import random

class TokenManager(RelationalMixin):
    SQL_CREATE_TABLES = "token_tables.sql"

    def consume(self, uuid):
        now = datetime.utcnow()
        retval = self.get(
            "select subject, mail, created, expires, profile from token where uuid = ? and created < ? and ? < expires and used is null",
            uuid,
            now + const.CLOCK_SKEW_TOLERANCE,
            now - const.CLOCK_SKEW_TOLERANCE)
        self.execute(
            "update token set used = ? where uuid = ?",
            now,
            uuid)
        return retval

    def issue(self, issuer, subject, subject_mail=None):
        # Expand variables
        subject_username = subject.name
        if not subject_mail:
            subject_mail = subject.mail

        # Generate token
        token = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(32))
        token_created = datetime.utcnow()
        token_expires = token_created + config.TOKEN_LIFETIME

        self.sql_execute("token_issue.sql",
            token_created, token_expires, token,
            issuer.name if issuer else None,
            subject_username, subject_mail, "rw")

        # Token lifetime in local time, to select timezone: dpkg-reconfigure tzdata
        try:
            with open("/etc/timezone") as fh:
                token_timezone = fh.read().strip()
        except EnvironmentError:
            token_timezone = None

        router = sorted([j[0] for j in authority.list_signed(
                    common_name=config.SERVICE_ROUTERS)])[0]
        protocols = ",".join(config.SERVICE_PROTOCOLS)
        url = config.TOKEN_URL % locals()

        context = globals()
        context.update(locals())

        mailer.send("token.md", to=subject_mail, **context)
        return {
            "token": token,
            "url": url,
        }

    def list(self, expired=False, used=False):
        stmt = "select created as 'created[timestamp]', expires as 'expires[timestamp]', used as 'used[timestamp]', issuer, mail, subject, substr(uuid, 0, 8) as uuid from token"
        where = []
        args = []
        if not expired:
            where.append(" expires > ?")
            args.append(datetime.utcnow())
        if not used:
            where.append(" used is null")
        if where:
            stmt = stmt + " where " + (" and ".join(where))
        stmt += " order by expires"
        return self.iterfetch(stmt, *args)

    def purge(self, all=False):
        stmt = "delete from token"
        args = []
        if not all:
            stmt += " where expires < ?"
            args.append(datetime.utcnow())
        return self.execute(stmt, *args)


from certidude import config
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize
from certidude.relational import RelationalMixin

class LogResource(RelationalMixin):
    SQL_CREATE_TABLES = "log_tables.sql"

    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        # TODO: Add last id parameter
        return self.iterfetch("select * from log order by created desc")

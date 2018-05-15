
from certidude.decorators import serialize
from certidude.relational import RelationalMixin
from .utils.firewall import login_required, authorize_admin

class LogResource(RelationalMixin):
    SQL_CREATE_TABLES = "log_tables.sql"

    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        # TODO: Add last id parameter
        return self.iterfetch("select * from log order by created desc limit ?",
            req.get_param_as_int("limit"))

create table if not exists log (
    created datetime,
    facility varchar(30),
    level int,
    severity varchar(10),
    message text,
    module varchar(20),
    func varchar(50),
    lineno int,
    exception text,
    process int,
    thread text,
    thread_name text
)

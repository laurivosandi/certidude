create table if not exists token (
    id integer primary key autoincrement,
    created datetime,
    used datetime,
    expires datetime,
    uuid char(32),
    issuer char(30),
    subject varchar(30),
    mail varchar(128),
    profile varchar(10),

    constraint unique_uuid unique(uuid)
)

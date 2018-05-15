insert into token (
    created,
    expires,
    uuid,
    issuer,
    subject,
    mail,
    profile
) values (
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?
);

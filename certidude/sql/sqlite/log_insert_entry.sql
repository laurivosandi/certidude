insert into log (
    created,
    facility,
    level,
    severity,
    message,
    module,
    func,
    lineno,
    exception,
    process,
    thread,
    thread_name
) values (
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?,
    ?
);

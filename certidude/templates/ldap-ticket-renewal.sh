#!/bin/bash
KRB5CCNAME={{ticket_path}}.part kinit -k {{name}}$ -S ldap/dc1.{{domain}}@{{realm}} -t /etc/krb5.keytab
chown certidude:certidude {{ticket_path}}.part
mv {{ticket_path}}.part {{ticket_path}}


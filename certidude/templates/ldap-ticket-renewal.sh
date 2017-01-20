#!/bin/bash
mkdir -p /run/certidude
KRB5CCNAME=/run/certidude/krb5cc.part kinit -k {{name}}$ -S ldap/dc1.{{domain}}@{{realm}} -t /etc/krb5.keytab
chown certidude:certidude /run/certidude/krb5cc.part
mv /run/certidude/krb5cc.part /run/certidude/krb5cc


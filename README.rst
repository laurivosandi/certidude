Certidude
=========

Introduction
------------

Certidude is a novel X.509 Certificate Authority management tool
with privilege isolation mechanism and Kerberos authentication aiming to
eventually support PKCS#11 and in far future WebCrypto.

.. figure:: doc/usecase-diagram.png

Certidude is mainly designed for VPN gateway operators to make VPN adoption usage
as simple as possible.
For a full-blown CA you might want to take a look at
`EJBCA <http://www.ejbca.org/features.html>`_ or
`OpenCA <https://pki.openca.org/>`_.


Features
--------

* Standard request, sign, revoke workflow via web interface.
* Colored command-line interface, check out ``certidude list``.
* OpenVPN integration, check out ``certidude setup openvpn server`` and ``certidude setup openvpn client``.
* strongSwan integration, check out ``certidude setup strongswan server`` and ``certidude setup strongswan client``.
* Privilege isolation, separate signer process is spawned per private key isolating
  private key use from the the web interface.
* Certificate numbering obfuscation, certificate serial numbers are intentionally
  randomized to avoid leaking information about business practices.
* Server-side events support via for example nginx-push-stream-module.
* Kerberos based web interface authentication.
* File based whitelist authorization, easy to integrate with LDAP as shown below.


Coming soon
-----------

* Refactor mailing subsystem and server-side events to use hooks.
* Notifications via e-mail.


TODO
----

* `OCSP <https://tools.ietf.org/html/rfc4557>`_ support, needs a bit hacking since OpenSSL wrappers are not exposing the functionality.
* `SECP <https://tools.ietf.org/html/draft-nourse-scep-23>`_ support, a client implementation available `here <https://github.com/certnanny/sscep>`_. Not sure if we can implement server-side events within current standard.
* Deep mailbox integration, eg fetch CSR-s from mailbox via IMAP.
* WebCrypto support, meanwhile check out `hwcrypto.js <https://github.com/open-eid/hwcrypto.js>`_.
* Certificate push/pull, making it possible to sign offline.
* PKCS#11 hardware token support for signatures at command-line.
* Ability to send ``.ovpn`` bundle URL tokens via e-mail, for simplified VPN adoption.
* Cronjob for deleting expired certificates
* Signer process logging.

Install
-------

To install Certidude:

.. code:: bash

    apt-get install -y python3 python3-pip python3-dev cython3 build-essential libffi-dev libssl-dev
    pip3 install certidude

Make sure you're running PyOpenSSL 0.15+ and netifaces 0.10.4+ from PyPI,
not the outdated ones provided by APT.

Create a system user for ``certidude``:

.. code:: bash

    adduser --system --no-create-home --group certidude


Setting up CA
--------------

Certidude can set up CA relatively easily:

.. code:: bash

    certidude setup authority /path/to/directory

Tweak command-line options until you meet your requirements and
then insert generated section to your /etc/ssl/openssl.cnf

Spawn the signer process:

.. code:: bash

    certidude spawn

Finally serve the certificate authority via web:

.. code:: bash

    certidude serve


Certificate management
----------------------

Use following command to request a certificate on a machine:

.. code::

    certidude setup client http://certidude-hostname-or-ip:perhaps-port/api/ca-name/

Use following to list signing requests, certificates and revoked certificates:

.. code::

    certidude list

Use web interface or following to sign a certificate on Certidude server:

.. code::

    certidude sign client-hostname-or-common-name


Production deployment
---------------------

Install ``nginx`` and ``uwsgi``:

.. code:: bash

    apt-get install nginx uwsgi uwsgi-plugin-python3

For easy setup following is reccommended:

.. code:: bash

    certidude setup production

Otherwise manually configure ``uwsgi`` application in ``/etc/uwsgi/apps-available/certidude.ini``:

.. code:: ini

    [uwsgi]
    master = true
    processes = 1
    vaccum = true
    uid = certidude
    gid = certidude
    plugins = python34
    pidfile = /run/certidude/api/uwsgi.pid
    socket = /run/certidude/api/uwsgi.sock
    chdir = /tmp
    module = certidude.wsgi
    callable = app
    chmod-socket = 660
    chown-socket = certidude:www-data
    buffer-size = 32768
    env = PUSH_PUBLISH=http://localhost/event/publish/%(channel)s
    env = PUSH_SUBSCRIBE=http://localhost/event/subscribe/%(channel)s
    env = LANG=C.UTF-8
    env = LC_ALL=C.UTF-8
    env = KRB5_KTNAME=/etc/certidude.keytab

Also enable the application:

.. code:: bash

    ln -s ../apps-available/certidude.ini /etc/uwsgi/apps-enabled/certidude.ini

We support `nginx-push-stream-module <https://github.com/wandenberg/nginx-push-stream-module>`_,
configure the site in /etc/nginx/sites-available.d/certidude:

.. code::

    upstream certidude_api {
        server unix:///run/certidude/api/uwsgi.sock;
    }

    server {
        server_name localhost;
        listen 80 default_server;
        listen [::]:80 default_server ipv6only=on;

        location ~ /event/publish/(.*) {
            allow 127.0.0.1; # Allow publishing only from this IP address
            push_stream_publisher admin;
            push_stream_channels_path $1;
        }

        location ~ /event/subscribe/(.*) {
            push_stream_channels_path $1;
            push_stream_subscriber long-polling;
        }

        location / {
            include uwsgi_params;
            uwsgi_pass certidude_api;
        }
    }

Enable the site:

.. code:: bash

    ln -s ../sites-available.d/certidude.ini /etc/nginx/sites-enabled.d/certidude

Also adjust ``/etc/nginx/nginx.conf``:

.. code::

    user www-data;
    worker_processes 4;
    pid /run/nginx.pid;

    events {
        worker_connections 768;
        # multi_accept on;
    }

    http {
        push_stream_shared_memory_size 32M;
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        gzip_disable "msie6";
        include /etc/nginx/sites-enabled/*;
    }

Restart the services:

.. code:: bash

    service uwsgi restart
    service nginx restart


Setting up Kerberos authentication
----------------------------------

Following assumes you have already set up Kerberos infrastructure and
Certidude is simply one of the servers making use of that infrastructure.

Install dependencies:

.. code:: bash

    apt-get install samba-common-bin krb5-user ldap-utils

Set up Samba client configuration in ``/etc/samba/smb.conf``:

.. code:: ini

    [global]
    security = ads
    netbios name = CERTIDUDE
    workgroup = WORKGROUP
    realm = EXAMPLE.LAN
    kerberos method = system keytab

Set up Kerberos keytab for the web service:

.. code:: bash

    KRB5_KTNAME=FILE:/etc/certidude.keytab net ads keytab add HTTP -U Administrator


Setting up authorization
------------------------

Obviously arbitrary Kerberos authenticated user should not have access to
the CA web interface.
You could either specify user name list
in ``/etc/ssl/openssl.cnf``:

.. code:: bash

    admin_users=alice bob john kate

Or alternatively specify file path:

.. code:: bash

    admin_users=/run/certidude/user.whitelist

Use following shell snippets eg in ``/etc/cron.hourly/update-certidude-user-whitelist``
to generate user whitelist via LDAP:

.. code:: bash

    ldapsearch -H ldap://dc1.example.com -s sub -x -LLL \
        -D 'cn=certidude,cn=Users,dc=example,dc=com' \
        -w 'certidudepass' \
        -b 'dc=example,dc=com' \
        '(&(objectClass=user)(memberOf=cn=Domain Admins,cn=Users,dc=example,dc=com))' sAMAccountName userPrincipalName givenName sn \
    | python3 -c "import ldif3; import sys; [sys.stdout.write('%s:%s:%s:%s\n' % (a.pop('sAMAccountName')[0], a.pop('userPrincipalName')[0], a.pop('givenName')[0], a.pop('sn')[0])) for _, a in ldif3.LDIFParser(sys.stdin.buffer).parse()]" \
    > /run/certidude/user.whitelist

Set permissions:

.. code:: bash

    chmod 700 /etc/cron.hourly/update-certidude-user-whitelist

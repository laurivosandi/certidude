Certidude
=========

Introduction
------------

Certidude is a novel X.509 Certificate Authority management tool
with privilege isolation mechanism aiming to
eventually support PKCS#11 and in far future WebCrypto.


Features
--------

* Standard request, sign, revoke workflow via web interface.
* Colored command-line interface, check out ``certidude list``
* OpenVPN integration, check out ``certidude setup openvpn server`` and ``certidude setup openvpn client``
* Privilege isolation, separate signer process is spawned per private key isolating
  private key use from the the web interface.
* Certificate numbering obfuscation, certificate serial numbers are intentionally
  randomized to avoid leaking information about business practices.
* Server-side events support via for example nginx-push-stream-module


TODO
----

* Refactor mailing subsystem and server-side events to use hooks.
* Notifications via e-mail.
* strongSwan setup integration.
* OCSP support.
* Deep mailbox integration, eg fetch CSR-s from mailbox via IMAP.
* WebCrypto support, meanwhile check out `hwcrypto.js <https://github.com/open-eid/hwcrypto.js>`_.
* Certificate push/pull, making it possible to sign offline.
* PKCS#11 hardware token support for signatures at command-line.


Install
-------

To install Certidude:

.. code:: bash

    apt-get install python3 python3-pip python3-dev cython3 build-essential libffi-dev libssl-dev
    pip3 install certidude
    
Create a user for ``certidude``:

.. code:: bash

    useradd certidude


Setting up CA
--------------

Certidude can set up CA relatively easily:

.. code:: bash

    certidude setup authority /path/to/directory

Tweak command-line options until you meet your requirements and
then insert generated section to your /etc/ssl/openssl.cnf

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

Install uWSGI:

.. code:: bash

    apt-get install uwsgi uwsgi-plugin-python3

Configure uUWSGI application in ``/etc/uwsgi/apps-available/certidude.ini``:

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
    env = CERTIDUDE_EVENT_PUBLISH=http://localhost/event/publish/%(channel)s
    env = CERTIDUDE_EVENT_SUBSCRIBE=http://localhost/event/subscribe/%(channel)s

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

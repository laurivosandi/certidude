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
* Colored command-line interface, check out ``butterknife list``
* OpenVPN integration, check out ``butterknife setup openvpn server`` and ``butterknife setup openvpn client``
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

    apt-get install python3 python3-dev build-essential
    pip3 install certidude
    

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


Streaming push support
----------------------

We support `nginx-push-stream-module <https://github.com/wandenberg/nginx-push-stream-module>`_,
configure it as follows to enable real-time responses to events:

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

        server {
            listen 80 default_server;
            listen [::]:80 default_server ipv6only=on;
            server_name localhost;

            location ~ /event/publish/(.*) {
                allow 127.0.0.1; # Allow publishing only from this IP address
                push_stream_publisher admin;
                push_stream_channels_path $1;
            }

            location ~ /event/subscribe/(.*) {
                push_stream_channels_path $1;
                push_stream_subscriber long-polling;
            }

            location /api/ {
                proxy_pass       http://127.0.0.1:9090/api/;
                proxy_set_header Host      $host;
                proxy_set_header X-Real-IP $remote_addr;
            }
        }
    }


For ``butterknife serve`` export environment variables:

.. code:: bash

    export CERTIDUDE_EVENT_PUBLISH = "http://localhost/event/publish/%s"
    export CERTIDUDE_EVENT_SUBSCRIBE = "http://localhost/event/subscribe/%s"
    certidude server -p 9090

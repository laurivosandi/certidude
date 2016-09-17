Certidude
=========

.. image:: https://travis-ci.org/laurivosandi/certidude.svg?branch=master
    :target: https://travis-ci.org/laurivosandi/certidude

.. image:: http://codecov.io/github/laurivosandi/certidude/coverage.svg?branch=master
    :target: http://codecov.io/github/laurivosandi/certidude?branch=master


Introduction
------------

Certidude is a novel X.509 Certificate Authority management tool
with privilege isolation mechanism and Kerberos authentication aiming to
eventually support PKCS#11 and in far future WebCrypto.

.. figure:: doc/usecase-diagram.png

Certidude is mainly designed for VPN gateway operators to make
desktop/laptop VPN setup as easy as possible.
User certificate management eg. for HTTPS is also made reasonably simple.
For a full-blown CA you might want to take a look at
`EJBCA <http://www.ejbca.org/features.html>`_ or
`OpenCA <https://pki.openca.org/>`_.


Features
--------

Common:

* Standard request, sign, revoke workflow via web interface.
* Kerberos and basic auth based web interface authentication.
* PAM and Active Directory compliant authentication backends: Kerberos single sign-on, LDAP simple bind.
* POSIX groups and Active Directory (LDAP) group membership based authorization.
* Command-line interface, check out ``certidude list``.
* Privilege isolation, separate signer process is spawned per private key isolating
  private key use from the the web interface.
* Certificate serial numbers are intentionally randomized to avoid leaking information about business practices.
* Server-side events support via `nchan <https://nchan.slact.net/>`_.
* E-mail notifications about pending, signed and revoked certificates.

Virtual private networking:

* OpenVPN integration, check out ``certidude setup openvpn server`` and ``certidude setup openvpn client``.
* strongSwan integration, check out ``certidude setup strongswan server`` and ``certidude setup strongswan client``.
* NetworkManager integration, check out ``certidude setup openvpn networkmanager`` and ``certidude setup strongswan networkmanager``.

HTTPS:

* P12 bundle generation for web browsers, seems to work well with Android
* HTTPS server setup with client verification, check out ``certidude setup nginx``


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

    apt-get install -y python python-pip python-dev cython \
        python-cffi python-configparser \
        python-pysqlite2 python-mysql.connector python-ldap \
        build-essential libffi-dev libssl-dev libkrb5-dev \
        ldap-utils krb5-user \
        libsasl2-modules-gssapi-mit \
        libsasl2-dev libldap2-dev
    pip install certidude


Setting up authority
--------------------

First make sure the machine used for certificate authority has fully qualified
domain name set up properly.
You can check it with:

.. code:: bash

    hostname -f

The command should return ``ca.example.com``.

If necessary tweak machine's fully qualified hostname in ``/etc/hosts``:

.. code::

    127.0.0.1 localhost
    127.0.1.1 ca.example.com ca

Then proceed to install `nchan <https://nchan.slact.net/>`_:

.. code:: bash

    wget https://nchan.slact.net/download/nginx-common.deb \
      https://nchan.slact.net/download/nginx-extras.deb
    dpkg -i nginx-common.deb nginx-extras.deb
    apt-get -f install

Certidude can set up certificate authority relatively easily.
Following will set up certificate authority in ``/var/lib/certidude/hostname.domain.tld``,
configure gunicorn service for your platform,
nginx in ``/etc/nginx/sites-available/certidude.conf``,
cronjobs in ``/etc/cron.hourly/certidude`` and much more:

.. code:: bash

    certidude setup authority

Tweak the configuration in ``/etc/certidude/server.conf`` until you meet your requirements and
spawn the signer process:

.. code:: bash

    certidude signer spawn

Finally restart services:

.. code:: bash

    service nginx restart
    service uwsgi restart


Certificate management
----------------------

Use following command to request a certificate on a machine:

.. code::

    certidude setup client ca.example.com

Use following to list signing requests, certificates and revoked certificates on server:

.. code::

    certidude list

Use web interface or following to sign a certificate on server:

.. code::

    certidude sign client-hostname-or-common-name


Setting up Active Directory authentication
------------------------------------------

Following assumes you have already set up Kerberos infrastructure and
Certidude is simply one of the servers making use of that infrastructure.

Install dependencies:

.. code:: bash

    apt-get install samba-common-bin krb5-user ldap-utils

Reset Samba client configuration in ``/etc/samba/smb.conf``, adjust
workgroup and realm accordingly:

.. code:: ini

    [global]
    security = ads
    netbios name = CA
    workgroup = EXAMPLE
    realm = EXAMPLE.COM
    kerberos method = system keytab

Reset Kerberos configuration in ``/etc/krb5.conf``:

.. code:: ini

    [libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true

Reset LDAP configuration in /etc/ldap/ldap.conf:

.. code:: bash

    BASE dc=example,dc=com
    URI ldap://dc1.example.com

Initialize Kerberos credentials:

.. code:: bash

    kinit administrator

Join the machine to domain:

.. code:: bash

    net ads join -k

Set up Kerberos keytab for the web service:

.. code:: bash

    KRB5_KTNAME=FILE:/etc/certidude/server.keytab net ads keytab add HTTP -k
    chown root:certidude /etc/certidude/server.keytab
    chmod 640 /etc/certidude/server.keytab

Reconfigure /etc/certidude/server.conf:

.. code:: ini

    [authentication]
    backends = kerberos

    [authorization]
    backend = ldap
    ldap gssapi credential cache = /run/certidude/krb5cc
    ldap user filter = (&(objectclass=user)(objectcategory=person)(samaccountname=%s))
    ldap admin filter = (&(memberOf=cn=Domain Admins,cn=Users,dc=example,dc=com)(samaccountname=%s))

User filter here specified which users can log in to Certidude web interface
at all eg. for generating user certificates for HTTPS.
Admin filter specifies which users are allowed to sign and revoke certificates.
Adjust admin filter according to your setup.
Also make sure there is cron.hourly job for creating GSSAPI credential cache -
that's necessary for querying LDAP using Certidude machine's credentials.

Common pitfalls:

* Following error message may mean that the IP address of the web server does not match the IP address used to join
  the CA machine to domain, eg when you're running CA behind SSL terminating web server:
  Bad credentials: Unspecified GSS failure.  Minor code may provide more information (851968)

Automating certificate setup
----------------------------

Ubuntu 14.04 based desktops come with NetworkManager installed.
Create ``/etc/NetworkManager/dispatcher.d/certidude`` with following content:

.. code:: bash

    #!/bin/sh -e
    # Set up certificates for IPSec connection

    case "$2" in
        up)
            LANG=C.UTF-8 /usr/local/bin/certidude request spawn -k
        ;;
    esac

Finally make it executable:

.. code:: bash

    chmod +x /etc/NetworkManager/dispatcher.d/certidude

Whenever a wired or wireless connection is brought up,
the dispatcher invokes ``certidude`` in order to generate RSA keys,
submit CSR, fetch signed certificate,
create NetworkManager configuration for the VPN connection.


Development
-----------

Clone the repository:

.. code:: bash

    git clone https://github.com/laurivosandi/certidude
    cd certidude

Install dependencies as shown above and additionally:

.. code:: bash

    pip install -r requirements.txt

To generate templates:

.. code:: bash

    apt-get install npm nodejs
    sudo ln -s nodejs /usr/bin/node # Fix 'env node' on Ubuntu 14.04
    npm install -g nunjucks
    nunjucks-precompile --include "\\.html$" --include "\\.svg$" certidude/static/ > certidude/static/js/templates.js

To run from source tree:

.. code:: bash

    PYTHONPATH=. KRB5CCNAME=/run/certidude/krb5cc KRB5_KTNAME=/etc/certidude/server.keytab LANG=C.UTF-8 python misc/certidude

To install the package from the source:

.. code:: bash

    python setup.py  install --single-version-externally-managed --root /

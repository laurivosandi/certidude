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

Certidude is mainly designed for StrongSwan and OpenVPN gateway operators to make
VPN client setup on laptops, desktops and mobile devices as painless as possible.
Certidude can also be used to manage HTTPS client certificates for
eg. maintaining an extra layer of protection for intranet websites.
For a full-blown CA you might want to take a look at
`EJBCA <http://www.ejbca.org/features.html>`_ or
`OpenCA <https://pki.openca.org/>`_.


Usecases
--------

Following usecases are covered:

* I am a sysadmin. Employees with different operating systems need to access
  internal network services over OpenVPN.
  I want to provide web interface for submitting the certificate signing request online.
  I want to get notified via e-mail when a user submits a certificate.
  Once I have signed the certificate I want the user to have easy way to download
  the signed certificate from the same web interface.
  Request submission and signing has to be visible in the web interface
  immediately. Common name is set to username.

* I am a sysadmin. I want to allow my Ubuntu roadwarriors to
  connect to network services at headquarters via IPSec.
  I want to make use of domain membership trust to automatically sign the certificates.
  Common name is set to computers hostname without the domain suffix.
  NetworkManager integration is necessary so the user can see the VPN connection state.
  Software installation and one simple configuration file should suffice to get up and running.

* I am a sysadmin. Employees need to get access to intranet wiki using
  HTTPS certificates possibly with multiple devices.
  Common name is set to username@device-identifier.
  The user logs in using domain account in the web interface and can automatically
  retrieve a P12 bundle which can be installed on her Android device.

Future usecases:

* I want to store the private key of my CA on a SmartCard.
  I want to make use of it while I log in to my CA web interface.
  When I am asked to sign a certificate I have to enter PIN code to unlock the
  SmartCard.


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

To install Certidude server you need certain system libraries in addition to
regular Python dependencies.

System dependencies for Ubuntu 16.04:

.. code:: bash

    apt install -y python python-pip python-dev cython \
        python-cffi python-configparser python-dateutil \
        python-pysqlite2 python-mysql.connector python-ldap \
        build-essential libffi-dev libssl-dev libkrb5-dev \
        ldap-utils krb5-user \
        libsasl2-modules-gssapi-mit \
        libsasl2-dev libldap2-dev

System dependencies for Fedora 24+:

.. code:: bash

    yum install redhat-rpm-config python-devel openssl-devel openldap-devel

At the moment package at PyPI is rather outdated.
Please proceed down to Development section to install Certidude from source.


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

Certidude can set up certificate authority relatively easily.
Following will set up certificate authority in ``/var/lib/certidude/hostname.domain.tld``,
configure systemd service for your platform,
nginx in ``/etc/nginx/sites-available/certidude.conf``,
cronjobs in ``/etc/cron.hourly/certidude`` and much more:

.. code:: bash

    certidude setup authority

Tweak the configuration in ``/etc/certidude/server.conf`` until you meet your requirements
and start the services:

.. code:: bash

    systemctl restart certidude


Setting up PAM authentication
-----------------------------

Following assumes the OS user accounts are used to authenticate users.
This means users can be easily managed with OS tools such as ``adduser``, ``usermod``, ``userdel`` etc.

Make sure you insert `AllowUsers administrator-account-username`
to SSH server configuration if you have SSH server installed on the machine
to prevent regular users from accessing the command line of certidude.
Note that in future we're planning to add command-line interaction
in which case SSH access makes sense.

If you're planning to use PAM for authentication you need to install corresponding
Python modules:

.. code:: bash

    pip install simplepam

The default configuration generated by ``certidude setup`` should make use of the
PAM.

Setting up Active Directory authentication
------------------------------------------

Following assumes you have already set up Kerberos infrastructure and
Certidude is simply one of the servers making use of that infrastructure.

Install dependencies:

.. code:: bash

    apt-get install samba-common-bin krb5-user ldap-utils
    pip install pykerberos

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


Setting up services
-------------------

Set up services as usual (OpenVPN, Strongswan, etc), when setting up certificates
generate signing request with TLS server flag set.
Paste signing request into the Certidude web interface and hit the submit button.

Since signing requests with custom flags are not allowed to be signed
from the interface due to security concerns, sign the certificate at Certidude command line:

.. code:: bash

    certidude sign gateway.example.com

Download signed certificate from the web interface or ``wget`` it into the service machine.
Fetch also CA certificate and finish configuring the service.


Setting up clients
------------------

This example works for Ubuntu 16.04 desktop with corresponding plugins installed
for NetworkManager.

Configure Certidude client in ``/etc/certidude/client.conf``:

.. code:: ini

    [ca.example.com]
    insecure = true
    trigger = interface up

Configure services in ``/etc/certidude/services.conf``:

.. code:: bash

    [gateway.example.com]
    authority = ca.example.com
    service = network-manager/openvpn
    remote = gateway.example.com

To request certificate:

.. code:: bash

    certidude request

The keys, signing requests, certificates and CRL-s are placed under
/var/lib/certidude/ca.example.com/

The VPN connection should immideately become available under network connections.


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

    apt install npm nodejs
    sudo ln -s nodejs /usr/bin/node # Fix 'env node' on Ubuntu 14.04
    npm install -g nunjucks@2.5.2
    nunjucks-precompile --include "\\.html$" --include "\\.svg$" certidude/static/ > certidude/static/js/templates.js
    cp /usr/local/lib/node_modules/nunjucks/browser/*.js certidude/static/js/

To run from source tree:

.. code:: bash

    PYTHONPATH=. KRB5CCNAME=/run/certidude/krb5cc KRB5_KTNAME=/etc/certidude/server.keytab LANG=C.UTF-8 python misc/certidude

To install the package from the source:

.. code:: bash

    python setup.py  install --single-version-externally-managed --root /

To uninstall:

    pip uninstall certidude


Certificate attributes
----------------------

Certificates have a lot of fields that can be filled in.
In any case country, state, locality, organization, organizational unit are not filled in
as this information will already exist in AD and duplicating it in the certificate management
doesn't make sense. Additionally the information will get out of sync if
attributes are changed in AD but certificates won't be updated.

If machine is enrolled, eg by running certidude request:

* If Kerberos credentials are presented machine is automatically enrolled
* Common name is set to short hostname/machine name in AD
* E-mail is not filled in (maybe we can fill in something from AD?)
* Given name and surname are not filled in

If user enrolls, eg by clicking generate bundle button in the web interface:

* Common name is either set to username or username@device-identifier depending on the 'user certificate enrollment' setting
* Given name and surname are filled in based on LDAP attributes of the user
* E-mail not filled in (should it be filled in? Can we even send mail to user if it's in external domain?)

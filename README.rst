Certidude
=========

Certidude is a novel X.509 Certificate Authority management tool aiming to
support PKCS#11 and in far future WebCrypto

Install
-------

To install Certidude:

.. code:: bash

    apt-get install python3-openssl
    pip3 install certidude
    

Setting up CA
--------------

Certidude can set up CA relatively easily:

.. code:: bash

    certidude ca create /path/to/directory

Tweak command-line options until you meet your requirements and
finally insert corresponding segment to your /etc/ssl/openssl.cnf

Finally serve the certificate authority via web:

.. code:: bash

    certidude serve

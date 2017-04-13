#!/usr/bin/env python3
# coding: utf-8
import os
from setuptools import setup

setup(
    name = "certidude",
    version = "0.1.21",
    author = u"Lauri Võsandi",
    author_email = "lauri.vosandi@gmail.com",
    description = "Certidude is a novel X.509 Certificate Authority management tool aiming to support PKCS#11 and in far future WebCrypto.",
    license = "MIT",
    keywords = "falcon http jinja2 x509 pkcs11 webcrypto kerberos ldap",
    url = "http://github.com/laurivosandi/certidude",
    packages=[
        "certidude",
        "certidude.api"
    ],
    long_description=open("README.rst").read(),
    # Include here only stuff required to run certidude client
    install_requires=[
        "click",
        "cryptography",
        "configparser",
        "jinja2",
        "requests",
        "requests-kerberos"
    ],
    scripts=[
        "misc/certidude"
    ],
    include_package_data = True,
    package_data={
        "certidude": ["certidude/templates/*"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: Freely Distributable",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
    ],
)


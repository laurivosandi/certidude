
import os
import click
import subprocess
from setproctitle import getproctitle
from random import SystemRandom

random = SystemRandom()

try:
    from time import time_ns
except ImportError:
    from time import time
    def time_ns():
        return int(time() * 10**9) # 64 bits integer, 32 ns bits

MAPPING = dict(
    common_name="CN",
    organizational_unit_name="OU",
    organization_name="O",
    domain_component="DC"
)

def cert_to_dn(cert):
    d = []
    for key, value in cert["tbs_certificate"]["subject"].native.items():
        if not isinstance(value, list):
            value = [value]
        for comp in value:
            d.append("%s=%s" % (MAPPING[key], comp))
    return ", ".join(d)

def cn_to_dn(common_name, namespace, o=None, ou=None):
    from asn1crypto.x509 import Name, RelativeDistinguishedName, NameType, DirectoryString, RDNSequence, NameTypeAndValue, UTF8String, DNSName

    rdns = []

    for dc in reversed(namespace.split(".")):
        rdns.append(RelativeDistinguishedName([
            NameTypeAndValue({
                'type': NameType.map("domain_component"),
                'value': DNSName(value=dc)
            })
        ]))

    if o:
        rdns.append(RelativeDistinguishedName([
            NameTypeAndValue({
                'type': NameType.map("organization_name"),
                'value': DirectoryString(
                    name="utf8_string",
                    value=UTF8String(o))
            })
        ]))

    if ou:
        rdns.append(RelativeDistinguishedName([
            NameTypeAndValue({
                'type': NameType.map("organizational_unit_name"),
                'value': DirectoryString(
                    name="utf8_string",
                    value=UTF8String(ou))
            })
        ]))

    rdns.append(RelativeDistinguishedName([
        NameTypeAndValue({
            'type': NameType.map("common_name"),
            'value': DirectoryString(
                name="utf8_string",
                value=UTF8String(common_name))
        })
    ]))

    return Name(name='', value=RDNSequence(rdns))

def selinux_fixup(path):
    """
    Fix OpenVPN credential store security context on Fedora
    """
    if os.path.exists("/usr/bin/chcon"):
        cmd = "chcon", "--type=home_cert_t", path
        subprocess.call(cmd)

def drop_privileges():
    from certidude import config
    import pwd
    _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
    restricted_groups = []
    restricted_groups.append(gid)

    # PAM needs access to /etc/shadow
    if config.AUTHENTICATION_BACKENDS == {"pam"}:
        import grp
        name, passwd, num, mem = grp.getgrnam("shadow")
        click.echo("Adding current user to shadow group due to PAM authentication backend")
        restricted_groups.append(num)

    os.setgroups(restricted_groups)
    os.setgid(gid)
    os.setuid(uid)
    click.echo("Switched %s (pid=%d) to user %s (uid=%d, gid=%d); member of groups %s" %
        (getproctitle(), os.getpid(), "certidude", os.getuid(), os.getgid(), ", ".join([str(j) for j in os.getgroups()])))
    os.umask(0o007)

def apt(packages):
    """
    Install packages for Debian and Ubuntu
    """
    if os.path.exists("/usr/bin/apt-get"):
        cmd = ["/usr/bin/apt-get", "install", "-yqq", "-o", "Dpkg::Options::=--force-confold"] + packages.split(" ")
        click.echo("Running: %s" % " ".join(cmd))
        subprocess.call(cmd)
        return True
    return False


def rpm(packages):
    """
    Install packages for Fedora and CentOS
    """
    if os.path.exists("/usr/bin/dnf"):
        cmd = ["/usr/bin/dnf", "install", "-y"] + packages.split(" ")
        click.echo("Running: %s" % " ".join(cmd))
        subprocess.call(cmd)
        return True
    return False


def pip(packages):
    click.echo("Running: pip3 install %s" % packages)
    import pip
    pip.main(['install'] + packages.split(" "))
    return True

def generate_serial():
    return time_ns() << 56 | random.randint(0, 2**56-1)


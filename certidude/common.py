
import os
import click
import subprocess

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
    click.echo("Switched to user %s (uid=%d, gid=%d); member of groups %s" %
        ("certidude", os.getuid(), os.getgid(), ", ".join([str(j) for j in os.getgroups()])))
    os.umask(0o007)

def ip_network(j):
    import ipaddress
    return ipaddress.ip_network(unicode(j))

def ip_address(j):
    import ipaddress
    return ipaddress.ip_address(unicode(j))

def apt(packages):
    """
    Install packages for Debian and Ubuntu
    """
    if os.path.exists("/usr/bin/apt-get"):
        cmd = ["/usr/bin/apt-get", "install", "-yqq"] + packages.split(" ")
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
    click.echo("Running: pip install %s" % packages)
    import pip
    pip.main(['install'] + packages.split(" "))
    return True


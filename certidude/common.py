
import os
import click
import subprocess

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

def expand_paths():
    """
    Prefix '..._path' keyword arguments of target function with 'directory' keyword argument
    and create the directory if necessary

    TODO: Move to separate file
    """
    def wrapper(func):
        def wrapped(**arguments):
            d = arguments.get("directory")
            for key, value in arguments.items():
                if key.endswith("_path"):
                    if d:
                        value = os.path.join(d, value)
                    value = os.path.realpath(value)
                    parent = os.path.dirname(value)
                    if not os.path.exists(parent):
                        click.echo("Making directory %s for %s" % (repr(parent), repr(key)))
                        os.makedirs(parent)
                    elif not os.path.isdir(parent):
                        raise Exception("Path %s is not directory!" % parent)
                    arguments[key] = value
            return func(**arguments)
        return wrapped
    return wrapper


def apt(packages):
    """
    Install packages for Debian and Ubuntu
    """
    if os.path.exists("/usr/bin/apt-get"):
        cmd = ["/usr/bin/apt-get", "install", "-yqq"] + packages.split(" ")
        click.echo("Running: %s" % " ".join(cmd))
        subprocess.call(cmd)


def rpm(packages):
    """
    Install packages for Fedora and CentOS
    """
    if os.path.exists("/usr/bin/dnf"):
        cmd = ["/usr/bin/dnf", "install", "-y"] + packages.split(" ")
        click.echo("Running: %s" % " ".join(cmd))
        subprocess.call(cmd)


def pip(packages):
    click.echo("Running: pip install %s" % packages)
    import pip
    pip.main(['install'] + packages.split(" "))


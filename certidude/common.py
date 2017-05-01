
import os
import click
import subprocess

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


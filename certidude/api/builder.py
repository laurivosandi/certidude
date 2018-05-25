
import click
import falcon
import logging
import os
import subprocess
from certidude import config, const, authority
from certidude.common import cert_to_dn
from ipaddress import ip_network
from jinja2 import Template
from .utils.firewall import login_required, authorize_admin

logger = logging.getLogger(__name__)

class ImageBuilderResource(object):
    @login_required
    @authorize_admin
    def on_get(self, req, resp, profile, suggested_filename):
        router = [j[0] for j in authority.list_signed(
            common_name=config.cp2.get(profile, "router"))][0]
        subnets = set([ip_network(j) for j in config.cp2.get(profile, "subnets").replace(",", " ").split(" ")])
        model = config.cp2.get(profile, "model")
        build_script_path = config.cp2.get(profile, "command")
        overlay_path = config.cp2.get(profile, "overlay")
        site_script_path = config.cp2.get(profile, "script")
        suffix = config.cp2.get(profile, "filename")

        build = "/var/lib/certidude/builder/" + profile
        log_path = build + "/build.log"
        if not os.path.exists(build + "/overlay/etc/uci-defaults"):
            os.makedirs(build + "/overlay/etc/uci-defaults")
        os.system("rsync -av " + overlay_path + "/ " + build + "/overlay/")

        if site_script_path:
            template = Template(open(site_script_path).read())
            with open(build + "/overlay/etc/uci-defaults/99-site-config", "w") as fh:
                fh.write(template.render(authority_name=const.FQDN))

        proc = subprocess.Popen(("/bin/bash", build_script_path),
            stdout=open(log_path, "w"), stderr=subprocess.STDOUT,
            close_fds=True, shell=False,
            cwd=os.path.dirname(os.path.realpath(build_script_path)),
            env={"PROFILE": model, "PATH":"/usr/sbin:/usr/bin:/sbin:/bin",
                "ROUTER": router,
                "IKE": config.cp2.get(profile, "ike"),
                "ESP": config.cp2.get(profile, "esp"),
                "SUBNETS": ",".join(str(j) for j in subnets),
                "AUTHORITY_CERTIFICATE_ALGORITHM": authority.public_key.algorithm,
                "AUTHORITY_CERTIFICATE_DISTINGUISHED_NAME": cert_to_dn(authority.certificate),
                "BUILD":build, "OVERLAY":build + "/overlay/"},
            startupinfo=None, creationflags=0)
        proc.communicate()
        if proc.returncode:
            logger.info("Build script finished with non-zero exitcode, see %s for more information" % log_path)
            raise falcon.HTTPInternalServerError("Build script finished with non-zero exitcode")

        for dname in os.listdir(build):
            if dname.startswith("lede-imagebuilder-"):
                for root, dirs, files in os.walk(os.path.join(build, dname, "bin", "targets")):
                    for filename in files:
                        if filename.endswith(suffix):
                            path = os.path.join(root, filename)
                            click.echo("Serving: %s" % path)
                            resp.body = open(path, "rb").read()
                            resp.set_header("Content-Disposition", ("attachment; filename=%s" % suggested_filename))
                            return
        raise falcon.HTTPNotFound()


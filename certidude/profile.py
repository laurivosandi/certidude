
import click
from datetime import timedelta
from certidude import const

class SignatureProfile(object):
    def __init__(self, slug, title, ou, ca, lifetime, key_usage, extended_key_usage, common_name):
        self.slug = slug
        self.title = title
        self.ou = ou or None
        self.ca = ca
        self.lifetime = lifetime
        self.key_usage = set(key_usage.split(" ")) if key_usage else set()
        self.extended_key_usage = set(extended_key_usage.split(" ")) if extended_key_usage else set()
        if common_name.startswith("^"):
            self.common_name = common_name
        elif common_name == "RE_HOSTNAME":
            self.common_name = const.RE_HOSTNAME
        elif common_name == "RE_FQDN":
            self.common_name = const.RE_FQDN
        elif common_name == "RE_COMMON_NAME":
            self.common_name = const.RE_COMMON_NAME
        else:
            raise ValueError("Invalid common name constraint %s" % common_name)

    @classmethod
    def from_cert(self, cert):
        """
        Derive signature profile from an already signed certificate, eg for renewal
        """
        lifetime = cert["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None) - \
            cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None)
        return SignatureProfile(
            None, "Renewal", cert.subject.native.get("organizational_unit_name"),
            cert.ca, lifetime.days,
            " ".join(cert.key_usage_value.native),
            " ".join(cert.extended_key_usage_value.native), "^")


    def serialize(self):
        return dict([(key, getattr(self,key)) for key in (
            "slug", "title", "ou", "ca", "lifetime", "key_usage", "extended_key_usage", "common_name")])

    def __repr__(self):
        bits = []
        if self.lifetime >= 365:
            bits.append("%d years" % (self.lifetime / 365))
        if self.lifetime % 365:
            bits.append("%d days" % (self.lifetime % 365))
        return "%s (title=%s, ca=%s, ou=%s, lifetime=%s, key_usage=%s, extended_key_usage=%s, common_name=%s)" % (
            self.slug, self.title, self.ca, self.ou, " ".join(bits), self.key_usage, self.extended_key_usage, self.common_name)


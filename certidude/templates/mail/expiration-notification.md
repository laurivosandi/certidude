{% if expired %}{{ expired | length }} have expired{% endif %}{% if expired and about_to_expire %}, {% endif %}{% if about_to_expire %}{{ about_to_expire | length }} about to expire{% endif %}

{% if about_to_expire %}
Following certificates are about to expire within following 48 hours:

{% for common_name, path, cert in expired %}
  * {{ common_name }}, {{ "%x" % cert.serial_number }}
{% endfor %}
{% endif %}

{% if expired %}
Following certificates have expired:

{% for common_name, path, cert in expired %}
  * {{ common_name }}, {{ "%x" % cert.serial_number }}
{% endfor %}
{% endif %}


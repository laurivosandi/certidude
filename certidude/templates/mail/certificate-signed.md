Certificate {{certificate.common_name}} ({{certificate.serial_number}}) signed

This is simply to notify that certificate {{ certificate.common_name }}
was signed{% if signer %} by {{ signer }}{% endif %}.

Any existing certificates with the same common name were rejected by doing so
and services making use of those certificates might become unavailable.

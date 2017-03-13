Signed {{ common_name }} ({{ serial_number }})

This is simply to notify that certificate {{ common_name }}
with serial number {{ serial_number }}
was signed{% if signer %} by {{ signer }}{% endif %}.

The certificate is valid from {{ certificate.not_valid_before }} until
{{ certificate.not_valid_after }}.

Any existing certificates with the same common name were rejected by doing so
and services making use of those certificates might become unavailable.

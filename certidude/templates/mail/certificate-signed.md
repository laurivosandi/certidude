Signed {{ common_name.value }} ({{ cert_serial_hex }})

This is simply to notify that certificate {{ common_name.value }}
with serial number {{ cert_serial_hex }}
was signed{% if signer %} by {{ signer }}{% endif %}.

The certificate is valid from {{ cert.not_valid_before }} until
{{ cert.not_valid_after }}.

{% if overwritten %}
By doing so existing certificate with the same common name
and serial number {{ prev_serial_hex }} was rejected
and services making use of that certificate might become unavailable.
{% endif %}

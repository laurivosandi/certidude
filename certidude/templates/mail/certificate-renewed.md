Renewed {{ common_name.value }} ({{ cert_serial_hex }})

This is simply to notify that certificate for {{ common_name.value }}
was renewed and the serial number of the new certificate is {{ cert_serial_hex }}.

The new certificate is valid from {{ cert.not_valid_before }} until
{{ cert.not_valid_after }}.

Services making use of those certificates should continue working as expected.

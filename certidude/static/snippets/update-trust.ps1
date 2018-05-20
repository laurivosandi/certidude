# Install CA certificate
@"
{{ session.authority.certificate.blob }}"@ | Out-File ca_cert.pem
Import-Certificate -FilePath ca_cert.pem -CertStoreLocation Cert:\LocalMachine\Root

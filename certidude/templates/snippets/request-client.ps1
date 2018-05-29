# Generate keypair and submit CSR
{% if common_name %}$NAME = "{{ common_name }}"
{% else %}$NAME = $env:computername.toLower()
{% endif %}
@"
[NewRequest]
Subject = "CN=$NAME"
Exportable = FALSE
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = True
ProviderType = 12
RequestType = PKCS10
{% if session.authority.certificate.algorithm == "ec" %}ProviderName = "Microsoft Software Key Storage Provider"
KeyAlgorithm = ECDSA_P384
{% else %}ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
KeyLength = 2048
{% endif %}"@ | Out-File req.inf
C:\Windows\system32\certreq.exe -new -f -q req.inf host_csr.pem
Invoke-WebRequest `{% if token %}
  -Uri 'https://{{ session.authority.hostname }}:8443/api/token/?token={{ token }}' `
  -Method PUT `{% else %}
  -Uri 'https://{{ session.authority.hostname }}:8443/api/request/?wait=yes&autosign=yes' `
  -Method POST `{% endif %}
  -TimeoutSec 900 `
  -InFile host_csr.pem `
  -ContentType application/pkcs10 `
  -MaximumRedirection 3 -OutFile host_cert.pem

# Import certificate
Import-Certificate -FilePath host_cert.pem -CertStoreLocation Cert:\LocalMachine\My
{#

On Windows 7 the Import-Certificate cmdlet is missing,
but certutil.exe can be used instead:

C:\Windows\system32\certutil.exe -addstore My host_cert.pem

Everything seems to work except after importing the certificate
it is not properly associated with the private key,
that means "You have private key that corresponds to this certificate" is not
shown under "Valid from ... to ..." in MMC.
This results in error code 13806 during IKEv2 handshake and error message
"IKE failed to find valid machine certificate"

#}


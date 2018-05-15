# Install CA certificate
@"
{{ session.authority.certificate.blob }}"@ | Out-File ca_cert.pem
{% if session.authority.certificate.algorithm == "ec" %}
Import-Certificate -FilePath ca_cert.pem -CertStoreLocation Cert:\LocalMachine\Root
{% else %}
C:\Windows\system32\certutil.exe -addstore Root ca_cert.pem
{% endif %}

# Generate keypair and submit CSR
$hostname = $env:computername.ToLower()
@"
[NewRequest]
Subject = "CN=$hostname"
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
Invoke-WebRequest -TimeoutSec 900 -Uri 'https://{{ session.authority.hostname }}:8443/api/request/?wait=yes&autosign=yes' -InFile host_csr.pem -ContentType application/pkcs10 -Method POST  -MaximumRedirection 3 -OutFile host_cert.pem

# Import certificate
{% if session.authority.certificate.algorithm == "ec" %}Import-Certificate -FilePath host_cert.pem -CertStoreLocation Cert:\LocalMachine\My
{% else %}C:\Windows\system32\certutil.exe -addstore My host_cert.pem
{% endif %}

{% for router in session.service.routers %}
# Set up IPSec VPN tunnel to {{ router }}
Remove-VpnConnection -AllUserConnection -Force "IPSec to {{ router }}"
Add-VpnConnection `
    -Name "IPSec to {{ router }}" `
    -ServerAddress {{ router }} `
    -AuthenticationMethod MachineCertificate `
    -SplitTunneling `
    -TunnelType ikev2 `
    -PassThru -AllUserConnection
Set-VpnConnectionIPsecConfiguration `
    -ConnectionName "IPSec to {{ router }}" `
    -AuthenticationTransformConstants GCMAES128 `
    -CipherTransformConstants GCMAES128 `
    -EncryptionMethod AES256 `
    -IntegrityCheckMethod SHA384 `
    -DHGroup {% if session.authority.certificate.algorithm == "ec" %}ECP384{% else %}Group14{% endif %} `
    -PfsGroup {% if session.authority.certificate.algorithm == "ec" %}ECP384{% else %}PFS2048{% endif %} `
    -PassThru -AllUserConnection -Force
{% endfor %}

{#
AuthenticationTransformConstants - ESP integrity algorithm, one of: None MD596 SHA196 SHA256128 GCMAES128 GCMAES192 GCMAES256
CipherTransformConstants - ESP symmetric cipher, one of: DES DES3 AES128 AES192 AES256 GCMAES128 GCMAES192 GCMAES256
EncryptionMethod - IKE symmetric cipher, one of: DES DES3 AES128 AES192 AES256
IntegrityCheckMethod - IKE hash algorithm, one of: MD5 SHA196 SHA256 SHA384
DHGroup = IKE key exchange, one of: None Group1 Group2 Group14 ECP256 ECP384 Group24
PfsGroup = ESP key exchange, one of: None PFS1 PFS2 PFS2048 ECP256 ECP384 PFSMM PFS24
#}

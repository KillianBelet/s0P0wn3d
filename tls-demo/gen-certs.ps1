# Génère une autorité de certification (CA) + certificats serveur (SAN 127.0.0.1/localhost) et client.
# Fichiers créés dans .\certs (à ne JAMAIS committer). Usage : .\gen-certs.ps1
$ErrorActionPreference = 'Stop'
$ossl = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
Push-Location $PSScriptRoot
try {
    New-Item -ItemType Directory -Force certs | Out-Null
    Set-Location certs
    function Run { & $ossl @args 2>&1 | Out-Null; if ($LASTEXITCODE) { throw "openssl $($args[0]) a échoué" } }
    # Autorité de certification (auto-signée)
    Run req -x509 -newkey rsa:2048 -nodes -days 30 -keyout ca.key -out ca.crt -subj '/CN=TLS CA'
    # Serveur : signé par la CA, SAN = IP de loopback + localhost
    Run req -x509 -newkey rsa:2048 -nodes -days 30 -keyout server.key -out server.crt `
        -subj '/CN=localhost' -CA ca.crt -CAkey ca.key `
        -addext 'subjectAltName=IP:127.0.0.1,IP:192.168.76.1,DNS:localhost' -addext 'extendedKeyUsage=serverAuth'
    # Client : signé par la CA
    Run req -x509 -newkey rsa:2048 -nodes -days 30 -keyout client.key -out client.crt `
        -subj '/CN=tls-client' -CA ca.crt -CAkey ca.key -addext 'extendedKeyUsage=clientAuth'
    Write-Host 'Certificats générés dans certs\'
}
finally { Pop-Location }

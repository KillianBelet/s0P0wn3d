# Compile client.exe et server.exe (MSVC x64 + OpenSSL-Win64, /TC /W4 /WX).
$ErrorActionPreference = 'Stop'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$ossl   = 'C:\Program Files\OpenSSL-Win64'
Push-Location $PSScriptRoot
try {
    $flags = "/nologo /TC /W4 /WX /MD /I`"$ossl\include`""
    $link  = "/link /LIBPATH:`"$ossl\lib\VC\x64\MD`" libssl.lib libcrypto.lib ws2_32.lib"
    $cmd = "call `"$vcvars`" >nul && cl $flags /Fe:client.exe client.c tls.c $link && cl $flags /Fe:server.exe server.c tls.c $link"
    & cmd.exe /d /s /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "Compilation échouée ($LASTEXITCODE)" }
    # DLL OpenSSL à côté des .exe pour qu'ils se lancent sans toucher au PATH
    Copy-Item "$ossl\bin\libssl-4-x64.dll", "$ossl\bin\libcrypto-4-x64.dll" . -Force
    # Fichiers intermédiaires de compilation : inutiles une fois les .exe produits
    Remove-Item *.obj, *.exp, *.lib -ErrorAction SilentlyContinue
    Write-Host 'Compilation réussie : client.exe et server.exe'
}
finally { Pop-Location }

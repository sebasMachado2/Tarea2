Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Afirmar-Admin {
    $esAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $esAdmin) {
        Write-Host "ERROR"
        Pause
        exit 1
    }
}

function Leer-IPv4([string]$Prompt) {
    while ($true) {
        $s = (Read-Host $Prompt).Trim()

        if ($s -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            Write-Host "IP invalida. Debe ser en formato A.B.C.D (ej. 192.168.100.50)" -ForegroundColor Yellow
            continue
        }

        $parts = $s.Split('.')
        $ok = $true
        foreach ($p in $parts) {
            $n = 0
            if (-not [int]::TryParse($p, [ref]$n) -or $n -lt 0 -or $n -gt 255) { $ok = $false; break }
        }
        if (-not $ok) {
            Write-Host "IP invalida"
            continue
        }
        if ($s -eq "0.0.0.0" -or $s -eq "255.255.255.255") {
            Write-Host "IP invalida"
            continue
        }

        return $s
    }
}

function Convertir-IPv4AUInt32([string]$Ip) {
    $b = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    return ([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor ([uint32]$b[3])
}

function Convertir-UInt32AIPv4([uint32]$Value) {
    $b0 = ($Value -shr 24) -band 0xFF
    $b1 = ($Value -shr 16) -band 0xFF
    $b2 = ($Value -shr 8)  -band 0xFF
    $b3 = $Value -band 0xFF
    return "$b0.$b1.$b2.$b3"
}

function Convertir-PrefijoAMascara([int]$Prefix) {
    if ($Prefix -lt 0 -or $Prefix -gt 32) { throw "Prefijo invalido: $Prefix" }
    if ($Prefix -eq 0) { return "0.0.0.0" }
    $mask = [uint32]0
    for ($i=0; $i -lt $Prefix; $i++) { $mask = $mask -bor ([uint32]1 -shl (31 - $i)) }
    return Convertir-UInt32AIPv4 $mask
}

function Obtener-RedUInt32([string]$Ip, [string]$Mask) {
    $ipU = Convertir-IPv4AUInt32 $Ip
    $mU  = Convertir-IPv4AUInt32 $Mask
    return ($ipU -band $mU)
}

function Obtener-MascaraDelServidorParaIpOAlternativa([string]$Ip, [string]$FallbackMask = "255.255.255.0") {
    $ipU = Convertir-IPv4AUInt32 $Ip

    $addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -and $_.PrefixLength -and $_.IPAddress -ne "127.0.0.1" }

    foreach ($a in $addrs) {
        $mask = Convertir-PrefijoAMascara $a.PrefixLength
        $netA = Obtener-RedUInt32 $a.IPAddress $mask
        $netI = Obtener-RedUInt32 $Ip $mask
        if ($netA -eq $netI) {
            return @{ Mask = $mask; Prefix = [int]$a.PrefixLength }
        }
    }

    return @{ Mask = $FallbackMask; Prefix = 24 }
}

function Leer-IPv4EnMismaSubred([string]$Prompt, [string]$BaseIp, [string]$Mask) {
    $baseNet = Obtener-RedUInt32 $BaseIp $Mask
    while ($true) {
        $ip = Leer-IPv4 $Prompt
        $net = Obtener-RedUInt32 $ip $Mask
        if ($net -eq $baseNet) { return $ip }
        Write-Host "Debe estar en la misma subred"
    }
}

function Afirmar-InicioFinMismaSubredYOrden([string]$StartIp, [string]$EndIp, [string]$Mask) {
    $sU = Convertir-IPv4AUInt32 $StartIp
    $eU = Convertir-IPv4AUInt32 $EndIp

    if ($sU -ge $eU) {
        throw "Rango invalido"
    }

    $sNet = Obtener-RedUInt32 $StartIp $Mask
    $eNet = Obtener-RedUInt32 $EndIp   $Mask
    if ($sNet -ne $eNet) {
        throw "Rango invlido"
    }
}

function Leer-IPv4EnMisma24([string]$Prompt, [string]$BaseIp) {
    $baseParts = $BaseIp.Split('.')
    while ($true) {
        $ip = Leer-IPv4 $Prompt
        $p = $ip.Split('.')
        if ($p[0] -eq $baseParts[0] -and $p[1] -eq $baseParts[1] -and $p[2] -eq $baseParts[2]) {
            return $ip
        }
        Write-Host "Debe estar en la misma red"
    }
}

function Leer-RangoIPv4([string]$StartIp, [string]$EndIp) {
    $s = [System.Net.IPAddress]::Parse($StartIp).GetAddressBytes()
    $e = [System.Net.IPAddress]::Parse($EndIp).GetAddressBytes()
    $sv = ($s[0] -shl 24) + ($s[1] -shl 16) + ($s[2] -shl 8) + $s[3]
    $ev = ($e[0] -shl 24) + ($e[1] -shl 16) + ($e[2] -shl 8) + $e[3]
    return @($sv, $ev)
}

function Leer-TiempoConcesion {
    while ($true) {
        $raw = Read-Host "Tiempo de concesion (formato: DD:HH:MM)"
        if ($raw -match '^\d{2}:\d{2}:\d{2}$') {
            $d = [int]$raw.Substring(0,2)
            $h = [int]$raw.Substring(3,2)
            $m = [int]$raw.Substring(6,2)
            if ($h -le 23 -and $m -le 59) {
                return (New-TimeSpan -Days $d -Hours $h -Minutes $m)
            }
        }
        Write-Host "Formato invalido. (formato: DD:HH:MM)"
    }
}

function Es-RolDhcpInstalado {
    $f = Get-WindowsFeature -Name DHCP
    return ($f -and $f.Installed)
}

function Instalar-RolDhcpSilencioso {
    Write-Host "Instalando rol DHCP.."
    Install-WindowsFeature -Name DHCP -IncludeManagementTools | Out-Null
    Write-Host "Rol DHCP instalado."
}

function Reinstalar-RolDhcpSilencioso {
    Write-Host "Reinstalando rol DHCP.."
    Remove-WindowsFeature -Name DHCP | Out-Null
    Install-WindowsFeature -Name DHCP -IncludeManagementTools | Out-Null
    Write-Host "Rol DHCP reinstalado."
}

function Configurar-AmbitoDhcpInteractivo {
    Import-Module DhcpServer -ErrorAction Stop

    Write-Host "`n-- Parametros del DHCP --"
    $scopeName = Read-Host "Nombre descriptivo del ambito (Scope Name)"
    if ([string]::IsNullOrWhiteSpace($scopeName)) { $scopeName = "Scope-1" }

    $startIp = Leer-IPv4 "Rango inicial"

    $netInfo = Obtener-MascaraDelServidorParaIpOAlternativa $startIp "255.255.255.0"
    $subnetMask = $netInfo.Mask

    Write-Host "Mascara detectada para esa red: $subnetMask (prefijo /$($netInfo.Prefix))"

    $endIp   = Leer-IPv4EnMismaSubred "Rango final" $startIp $subnetMask
    Afirmar-InicioFinMismaSubredYOrden $startIp $endIp $subnetMask

    $gateway = Leer-IPv4EnMismaSubred "Gateway en la misma subred" $startIp $subnetMask
    $lease   = Leer-TiempoConcesion

    $scopeNetU = Obtener-RedUInt32 $startIp $subnetMask
    $scopeId   = Convertir-UInt32AIPv4 $scopeNetU

    $existing = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.ScopeId.IPAddressToString -eq $scopeId }
    if (-not $existing) {
        Add-DhcpServerv4Scope -Name $scopeName -StartRange $startIp -EndRange $endIp -SubnetMask $subnetMask -State Active | Out-Null
        Write-Host "Ambito creado: $scopeName ($scopeId /24) $startIp - $endIp"
    } else {
        Write-Host "El ambito $scopeId ya existe. Se actualizaran opciones/lease."
        if ($existing.Name -ne $scopeName -and -not [string]::IsNullOrWhiteSpace($scopeName)) {
            Set-DhcpServerv4Scope -ScopeId $scopeId -Name $scopeName | Out-Null
        }
        Set-DhcpServerv4Scope -ScopeId $scopeId -StartRange $startIp -EndRange $endIp | Out-Null
    }

    Set-DhcpServerv4Scope -ScopeId $scopeId -LeaseDuration $lease | Out-Null

    Set-DhcpServerv4OptionValue -ScopeId $scopeId -Router $gateway | Out-Null

    Set-Service -Name DHCPServer -StartupType Automatic
    Start-Service -Name DHCPServer

    Write-Host "Configuracion aplicada: Lease=$($lease.ToString()) Router=$gateway"
}

function Mostrar-MonitoreoDhcp {
    Import-Module DhcpServer -ErrorAction SilentlyContinue

    Write-Host "`n-- MONITOREO DHCP --"

    $installed = Es-RolDhcpInstalado
    Write-Host ("Rol DHCP instalado: " + $installed)

    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "Servicio DHCPServer no encontrado."
        return
    }

    Write-Host ("Servicio DHCPServer: " + $svc.Status)

    try {
        $scopes = Get-DhcpServerv4Scope
        if (-not $scopes) {
            Write-Host "No hay ambitos creados."
        } else {
            Write-Host "`n-- Ambitos --"
            $scopes | Select-Object `
                @{n="ScopeId";e={$_.ScopeId.IPAddressToString}},
                Name,
                State,
                StartRange,
                EndRange,
                LeaseDuration |
            Format-Table -AutoSize

            foreach ($s in $scopes) {
                $sid = $s.ScopeId.IPAddressToString

                Write-Host "`n-- Opciones del ambito $sid --"
                $opt = Get-DhcpServerv4OptionValue -ScopeId $sid -ErrorAction SilentlyContinue
                $router = ($opt | Where-Object { $_.OptionId -eq 3 }).Value
                if ($router) {
                    Write-Host ("Router: " + ($router -join ", "))
                } else {
                    Write-Host "Router: (no configurado)"
                }

                Write-Host "`n-- Leases activos en $sid --"
                $leases = Get-DhcpServerv4Lease -ScopeId $sid -ErrorAction SilentlyContinue |
                          Sort-Object LeaseExpiryTime -Descending
                if ($leases) {
                    $leases | Select-Object IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime | Format-Table -AutoSize
                } else {
                    Write-Host "No hay leases."
                }
            }
        }

    } catch {
        Write-Host "Error en monitoreo: $($_.Exception.Message)"
    }
}

function Reiniciar-ServiciosDhcp {
    Write-Host "`n-- Reiniciar servicio DHCP --"

    if (-not (Es-RolDhcpInstalado)) {
        Write-Host "El rol DHCP no esta instalado."
        return
    }

    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "No se encontro el servicio DHCP."
        return
    }

    $ans = Read-Host "Reiniciar el servicio DHCP? (S/N)"
    if ($ans -notmatch '^(S|s|SI|Si|si)$') {
        Write-Host "Cancelado."
        return
    }

    try {
        if ($svc.Status -eq 'Running') {
            Restart-Service -Name DHCPServer -Force
        } else {
            Start-Service -Name DHCPServer
        }

        $svc2 = Get-Service -Name DHCPServer
        Write-Host "DHCPServer ahora esta: $($svc2.Status)"
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)"
    }
}

function Mostrar-Menu {
    Clear-Host
    Write-Host "--------------------"
    Write-Host "      Menu DHCP     "
    Write-Host "--------------------"
    Write-Host "1) Verificar si DHCP esta instalado"
    Write-Host "2) Instalar DHCP"
    Write-Host "3) Configurar ambito"
    Write-Host "4) Monitoreo"
    Write-Host "5) Reiniciar servicios"
    Write-Host "6) Salir"
}

Afirmar-Admin

while ($true) {
    Mostrar-Menu
    $opt = Read-Host "Elige una opcion (1-6)"

    try {
        switch ($opt) {
            "1" {
                $installed = Es-RolDhcpInstalado
                if ($installed) {
                    Write-Host "El rol DHCP esta instalado."
                } else {
                    Write-Host "El rol DHCP no esta instalado."
                }
                Pause
            }

            "2" {
                if (Es-RolDhcpInstalado) {
                    $ans = Read-Host "DHCP ya esta instalado. Deseas reinstalar? (S/N)"
                    if ($ans -match '^(S|s|SI|Si|si)$') {
                        Reinstalar-RolDhcpSilencioso
                    } else {
                        Write-Host "No se reinstalo."
                    }
                } else {
                    Instalar-RolDhcpSilencioso
                }

                Pause
            }

            "3" {
                $ans2 = Read-Host "Deseas configurar un ambito ahora? (S/N)"
                if ($ans2 -match '^(S|s|SI|Si|si)$') {
                    Configurar-AmbitoDhcpInteractivo
                }
                Pause
            }

            "4" {
                Mostrar-MonitoreoDhcp
                Pause
            }

            "5" {
                Reiniciar-ServiciosDhcp
                Pause
            }

            "6" { break }

            default {
                Write-Host "Opcion invalida."
                Pause
            }
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)"
        Pause
    }
}

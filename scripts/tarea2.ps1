Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Afirmar-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Ejecuta PowerShell COMO ADMINISTRADOR."
    }
}

function Pausa-Enter {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar" | Out-Null
}

function Leer-SiNo([string]$Prompt, [bool]$DefaultSi = $true) {
    $suffix = if ($DefaultSi) { "[S/n]" } else { "[s/N]" }
    while ($true) {
        $r = (Read-Host "$Prompt $suffix").Trim()
        if ([string]::IsNullOrWhiteSpace($r)) { return $DefaultSi }
        if ($r -match '^(s|si|y|yes)$') { return $true }
        if ($r -match '^(n|no)$') { return $false }
        Write-Host "Responde S o N."
    }
}

function Probar-IPv4([string]$Ip) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $false }
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $false }
    if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    if ($Ip -eq "0.0.0.0" -or $Ip -eq "255.255.255.255") { return $false }
    return $true
}

function Leer-IPv4([string]$Prompt) {
    while ($true) {
        $ip = (Read-Host $Prompt).Trim()
        if (Probar-IPv4 $ip) { return $ip }
        Write-Host "IP invalida. No se permite 0.0.0.0 ni 255.255.255.255."
    }
}

function Leer-IPv4Opcional([string]$Prompt) {
    while ($true) {
        $ip = (Read-Host "$Prompt (opcional, ENTER para omitir)").Trim()
        if ([string]::IsNullOrWhiteSpace($ip)) { return $null }
        if (Probar-IPv4 $ip) { return $ip }
        Write-Host "IP invalida."
    }
}

function Convertir-AUInt32IPv4([string]$Ip) {
    $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [Array]::Reverse($b)
    return [BitConverter]::ToUInt32($b, 0)
}

function Convertir-DeUInt32IPv4([UInt32]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($b)
    return ([System.Net.IPAddress]::new($b)).ToString()
}

function Incrementar-IPv4([string]$Ip) {
    $n = Convertir-AUInt32IPv4 $Ip
    if ($n -ge [UInt32]::MaxValue) { throw "No se puede incrementar la IP." }
    return (Convertir-DeUInt32IPv4 ([UInt32]($n + 1)))
}

function Obtener-PrefijoPorDefectoDeIp([string]$Ip) {
    $parts = $Ip.Split('.')
    $a = [int]$parts[0]; $b = [int]$parts[1]
    if ($a -eq 10) { return 8 }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return 16 }
    if ($a -eq 192 -and $b -eq 168) { return 24 }
    return 24
}

function Obtener-MascaraDeSubredDesdePrefijo([int]$Prefix) {
    if ($Prefix -lt 0 -or $Prefix -gt 32) { throw "Prefijo invalido." }
    $mask = [UInt32]0
    if ($Prefix -eq 0) {
        $mask = [UInt32]0
    } else {
        $mask = [UInt32]([UInt32]::MaxValue -shl (32 - $Prefix))
    }
    return (Convertir-DeUInt32IPv4 $mask)
}

function Obtener-PrefijoDesdeMascara([string]$Mask) {
    if (-not (Probar-IPv4 $Mask)) { throw "Mascara invalida: $Mask" }

    $bytes = ([System.Net.IPAddress]::Parse($Mask)).GetAddressBytes()
    $prefix = 0
    $vistoNo255 = $false

    foreach ($b in $bytes) {
        switch ($b) {
            255 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 8 }
            254 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 7; $vistoNo255 = $true }
            252 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 6; $vistoNo255 = $true }
            248 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 5; $vistoNo255 = $true }
            240 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 4; $vistoNo255 = $true }
            224 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 3; $vistoNo255 = $true }
            192 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 2; $vistoNo255 = $true }
            128 { if ($vistoNo255) { throw "Mascara no contigua: $Mask" }; $prefix += 1; $vistoNo255 = $true }
            0   { $vistoNo255 = $true }
            default { throw "Mascara invalida/no soportada: $Mask" }
        }
    }
    return $prefix
}

function Obtener-DireccionDeRed([string]$Ip, [string]$Mask) {
    $ipN   = Convertir-AUInt32IPv4 $Ip
    $maskN = Convertir-AUInt32IPv4 $Mask
    return (Convertir-DeUInt32IPv4 ([UInt32]($ipN -band $maskN)))
}

function Afirmar-MismaSubredYOrden([string]$StartIp, [string]$EndIp, [string]$Mask) {
    $n1 = Obtener-DireccionDeRed $StartIp $Mask
    $n2 = Obtener-DireccionDeRed $EndIp   $Mask
    if ($n1 -ne $n2) { throw "IP inicial y final NO estan en la misma subred (mascara $Mask)." }

    $s = Convertir-AUInt32IPv4 $StartIp
    $e = Convertir-AUInt32IPv4 $EndIp
    if ($e -le $s) { throw "La IP final debe ser mayor que la IP inicial." }
}

function Seleccionar-AliasInterfaz {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Sort-Object -Property Name
    if (-not $adapters) { throw "No hay adaptadores." }

    Write-Host ""
    Write-Host "Interfaces disponibles:"
    for ($i=0; $i -lt $adapters.Count; $i++) {
        $a = $adapters[$i]
        Write-Host ("[{0}] {1}  (Alias: {2})" -f ($i+1), $a.InterfaceDescription, $a.Name)
    }

    while ($true) {
        $sel = (Read-Host "Elige el numero de la interfaz donde estara el DHCP").Trim()
        if ($sel -match '^\d+$') {
            $idx = [int]$sel - 1
            if ($idx -ge 0 -and $idx -lt $adapters.Count) { return $adapters[$idx].Name }
        }
        Write-Host "Seleccion invalida."
    }
}

function Establecer-IPv4EstaticaEnInterfaz([string]$InterfaceAlias, [string]$Ip, [string]$Mask, [string[]]$DnsServersOptional) {
    $prefix = Obtener-PrefijoDesdeMascara $Mask

    Write-Host ""
    Write-Host "AVISO: Se asignara IP estatica $Ip/$prefix en '$InterfaceAlias'. Esto puede cortar conectividad si estas conectado por esa interfaz."

    Set-NetIPInterface -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -Dhcp Disabled | Out-Null

    $existing = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike "169.254.*" }
    foreach ($x in $existing) {
        if ($x.IPAddress -ne $Ip) {
            Remove-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $x.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    $has = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -eq $Ip }
    if (-not $has) {
        New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $Ip -PrefixLength $prefix -Type Unicast | Out-Null
    }

    if ($DnsServersOptional -and $DnsServersOptional.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServersOptional | Out-Null
    }
}

function Es-RolDhcpInstalado {
    $f = Get-WindowsFeature -Name DHCP -ErrorAction Stop
    return ($f -and $f.Installed)
}

function Instalar-RolDhcp([bool]$Reinstalar) {
    if (Es-RolDhcpInstalado) {
        if (-not $Reinstalar) {
            Write-Host "DHCP Server YA esta instalado."
            return
        }
        Write-Host "Reinstalando DHCP Server..."
        Uninstall-WindowsFeature -Name DHCP -Remove -Restart:$false | Out-Null
    }

    Write-Host "Instalando DHCP Server..."
    Install-WindowsFeature -Name DHCP -IncludeManagementTools -Restart:$false | Out-Null

    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayGroup -like "*DHCP*" } |
        Set-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Out-Null

    Start-Service -Name DHCPServer -ErrorAction SilentlyContinue
    Set-Service   -Name DHCPServer -StartupType Automatic -ErrorAction SilentlyContinue

    Write-Host "Instalacion completada."
}

function Configurar-Ambito {
    if (-not (Es-RolDhcpInstalado)) { throw "DHCP Server NO esta instalado." }

    Import-Module DhcpServer -ErrorAction Stop

    Write-Host ""
    Write-Host "=== Configurar Ambito (Scope) ==="

    $scopeName = (Read-Host "Nombre del ambito").Trim()
    if ([string]::IsNullOrWhiteSpace($scopeName)) { $scopeName = "Scope-1" }

    $serverIp = Leer-IPv4 "Rango inicial "

    $prefix = Obtener-PrefijoPorDefectoDeIp $serverIp
    $mask   = Obtener-MascaraDeSubredDesdePrefijo $prefix
    Write-Host "Mascara calculada desde la IP inicial: $mask (/$prefix)"

    $endIp = Leer-IPv4 "Rango final"
    Afirmar-MismaSubredYOrden $serverIp $endIp $mask

    $poolStart = Incrementar-IPv4 $serverIp
    if ((Convertir-AUInt32IPv4 $poolStart) -gt (Convertir-AUInt32IPv4 $endIp)) {
        throw "El pool quedaria vacio."
    }

    $gateway = Leer-IPv4Opcional "Gateway"
    if ($gateway) {
        if ((Obtener-DireccionDeRed $gateway $mask) -ne (Obtener-DireccionDeRed $serverIp $mask)) {
            throw "El Gateway no esta en la misma subred que el ambito."
        }
    }

    $dns1 = Leer-IPv4Opcional "DNS primario"
    $dns2 = $null
    if ($dns1) {
        $dns2 = Leer-IPv4Opcional "DNS secundario"
    }


    $dnsList = @()
    if ($dns1) { $dnsList += $dns1 }
    if ($dns2) { $dnsList += $dns2 }

    while ($true) {
        $raw = (Read-Host "Tiempo de concesion en segundos").Trim()
        if ($raw -match '^\d+$') {
            $leaseSeconds = [int]$raw
            if ($leaseSeconds -gt 0 -and $leaseSeconds -le 100000000 { break }
        }
        Write-Host "Valor invalido. Ingresa un entero > 0."
    }
    $leaseDuration = New-TimeSpan -Seconds $leaseSeconds

    $iface = Seleccionar-AliasInterfaz
    Establecer-IPv4EstaticaEnInterfaz -InterfaceAlias $iface -Ip $serverIp -Mask $mask -DnsServersOptional $dnsList

    $scopeIdStr = Obtener-DireccionDeRed $serverIp $mask
    $scopeId = [System.Net.IPAddress]::Parse($scopeIdStr)

    $existingScope = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue |
        Where-Object { $_.ScopeId -eq $scopeId }
    if ($existingScope) {
        $overwrite = Leer-SiNo "Ya existe un ambito con ScopeId $scopeIdStr. Quieres reemplazarlo?" $false
        if (-not $overwrite) { Write-Host "Cancelado."; return }
        Remove-DhcpServerv4Scope -ScopeId $scopeId -Force -ErrorAction SilentlyContinue
    }

    Add-DhcpServerv4Scope -Name $scopeName -StartRange $poolStart -EndRange $endIp -SubnetMask $mask | Out-Null
    Set-DhcpServerv4Scope -ScopeId $scopeId -State Active -LeaseDuration $leaseDuration | Out-Null

    if ($gateway) {
        Set-DhcpServerv4OptionValue -ScopeId $scopeId -Router $gateway | Out-Null
    }
    if ($dnsList -and $dnsList.Count -gt 0) {
        Set-DhcpServerv4OptionValue -ScopeId $scopeId -DnsServer $dnsList | Out-Null
    }

    Restart-Service -Name DHCPServer -Force
}

function Mostrar-Monitoreo {
    
    Write-Host ""
    Write-Host "--- Monitoreo DHCP ---"

    $installed = $false
    try { $installed = Es-RolDhcpInstalado } catch { $installed = $false }

    if (-not $installed) {
        Write-Host "DHCP no esta instalado."
        return
    }

    Import-Module DhcpServer -ErrorAction Stop

    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if (-not $scopes) {
        Write-Host "No hay configuracion todavia."
        return
    }

    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($svc) {
        $startMode = ""
        try { $startMode = (Get-CimInstance Win32_Service -Filter "Name='DHCPServer'").StartMode } catch { $startMode = "N/A" }
        Write-Host ("Servicio DHCPServer: {0} / StartupType: {1}" -f $svc.Status, $startMode)
    } else {
        Write-Host "Servicio DHCP: no encontrado."
    }

    Write-Host ""
    Write-Host "--- Ambitos ---"
    $scopes | Select-Object Name, ScopeId, StartRange, EndRange, SubnetMask, State, LeaseDuration | Format-Table -AutoSize

    foreach ($s in $scopes) {
        Write-Host ""
        Write-Host ("--- Leases del Scope {0} ({1}) ---" -f $s.Name, $s.ScopeId)
        $leases = Get-DhcpServerv4Lease -ScopeId $s.ScopeId -ErrorAction SilentlyContinue
        if ($leases) {
            $leases | Sort-Object -Property IPAddress |
                Select-Object IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime |
                Format-Table -AutoSize
        } else {
            Write-Host "Aun no hay leases."
        }
    }
}


function Reiniciar-ServicioDhcp {
    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "Servicio DHCP no encontrado."
        return
    }
    Restart-Service -Name DHCPServer -Force
    Write-Host "Servicio reiniciado."
}

function Mostrar-Menu {
    Clear-Host
    Write-Host "-------------------------------"
    Write-Host "   MENU DHCP (Windows Server)  "
    Write-Host "-------------------------------"
    Write-Host "1) Verificar si DHCP esta instalado"
    Write-Host "2) Instalar DHCP "
    Write-Host "3) Configurar ambito "
    Write-Host "4) Monitoreo"
    Write-Host "5) Reiniciar servicio DHCP"
    Write-Host "6) Salir"
    Write-Host ""
}

try {
    Afirmar-Admin
    while ($true) {
        Mostrar-Menu
        $opt = (Read-Host "Elige una opcion (1-6)").Trim()

        try {
            switch ($opt) {
                "1" {
                    Write-Host ""
                    $installed = $false
                    try { $installed = Es-RolDhcpInstalado } catch { $installed = $false }
                    $t = if ($installed) { "SI" } else { "NO" }
                    Write-Host ("DHCP instalado: {0}" -f $t)
                    Pausa-Enter
                }
                "2" {
                    $installed = $false
                    try { $installed = Es-RolDhcpInstalado } catch { $installed = $false }

                    if ($installed) {
                        $re = Leer-SiNo "DHCP ya esta instalado. Quieres REINSTALAR?" $false
                        Instalar-RolDhcp -Reinstalar:$re
                    } else {
                        Instalar-RolDhcp -Reinstalar:$false
                    }
                    Pausa-Enter
                }
                "3" {
                    Configurar-Ambito
                    Pausa-Enter
                }
                "4" {
                    Mostrar-Monitoreo
                    Pausa-Enter
                }
                "5" {
                    Reiniciar-ServicioDhcp
                    Pausa-Enter
                }
                "6" { break }
                default {
                    Write-Host "Opcion invalida."
                    Start-Sleep -Seconds 1
                }
            }
        } catch {
            Write-Host ""
            Write-Host ("ERROR: {0}" -f $_.Exception.Message)
            Pausa-Enter
        }
    }
} catch {
    Write-Host ("ERROR: {0}" -f $_.Exception.Message)
}

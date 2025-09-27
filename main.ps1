<#
.SYNOPSIS
  Mapeia hosts/servidores de VPN Cisco AnyConnect a partir de perfis XML, logs e conexões ativas (netstat),
  sem exigir privilégios de administrador. Também pode executar remotamente via PowerShell Remoting.

.PARAMETER ComputerName
  Opcional. Um ou mais computadores-alvo para executar remotamente. Se omitido, roda local.

.PARAMETER Credential
  Opcional. Credenciais para sessão remota (Get-Credential). Se omitido, usa contexto atual.

.PARAMETER Html
  Se presente, gera também um relatório HTML consolidado além do CSV.

.NOTES
  - Testado para contas não-admin: leitura de pastas públicas e execução de netstat.
  - Em ambientes onde o AnyConnect roda como serviço SYSTEM, ainda é possível correlacionar PID via `netstat -ano` + `Get-Process`.
  - Requisitos para remoto: WinRM habilitado, firewall liberado e permissão de logon remoto por PowerShell.

#>

[CmdletBinding()]
param(
  [string[]] $ComputerName,
  [System.Management.Automation.PSCredential] $Credential,
  [switch] $Html
)

$ErrorActionPreference = 'SilentlyContinue'
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmm')
$desktop   = [IO.Path]::Combine($env:USERPROFILE, 'Desktop')
$outCsv    = [IO.Path]::Combine($desktop, "cisco_anyconnect_hosts_$timestamp.csv")
$outHtml   = [IO.Path]::Combine($desktop, "cisco_anyconnect_hosts_$timestamp.html")

# --- Bloco de funções que será usado localmente e remotamente ---
$CoreScript = {
  param([switch]$ReturnRaw)

  function Try-ResolveHost {
    param([string]$Host)
    try {
      if (-not $Host) { return $null }
      if (Get-Command Resolve-DnsName -EA Ignore) {
        ($r = Resolve-DnsName -Name $Host -EA Stop) | Out-Null
        return ($r | ? IPAddress | % IPAddress) -join ','
      } else {
        return ([System.Net.Dns]::GetHostAddresses($Host) | % IPAddressToString) -join ','
      }
    } catch { return $null }
  }

  function Get-AnyConnectPaths {
    $p = @(
      "$env:ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile",
      "$env:ProgramFiles\Cisco\Cisco AnyConnect Secure Mobility Client\Profile",
      "$env:ProgramFiles(x86)\Cisco\Cisco AnyConnect Secure Mobility Client\Profile",
      "$env:LOCALAPPDATA\Cisco\Cisco AnyConnect Secure Mobility Client",
      "$env:USERPROFILE\AppData\Local\Cisco\Cisco AnyConnect Secure Mobility Client",
      "$env:ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\HostScan"
    )
    return $p | ? { $_ -and (Test-Path $_) }
  }

  function Get-FromProfilesAndLogs {
    $paths = Get-AnyConnectPaths
    $acc = New-Object System.Collections.Generic.List[object]

    # XML Profiles
    foreach ($b in $paths) {
      Get-ChildItem -Path $b -Filter *.xml -Recurse -EA Ignore | ForEach-Object {
        try {
          [xml]$doc = Get-Content -LiteralPath $_.FullName -EA Stop
          $nodes = @(); $nodes += $doc.SelectNodes("//HostEntry")
          foreach ($n in $nodes) {
            $host = $n.Host
            if ([string]::IsNullOrWhiteSpace($host)) { $host = $n.HostAddress }
            if ([string]::IsNullOrWhiteSpace($host) -and $n.SelectSingleNode('HostName')) {
              $host = $n.SelectSingleNode('HostName').InnerText
            }
            $friendly = $n.FriendlyName
            $acc.Add([pscustomobject]@{
              Source       = 'Profile XML'
              File         = $_.FullName
              FriendlyName = $friendly
              Host         = $host
              ResolvedIP   = Try-ResolveHost $host
              LastSeen     = $null
              Detail       = 'XML HostEntry'
              MachineName  = $env:COMPUTERNAME
              Username     = $env:USERNAME
            })
          }
        } catch {}
      }
    }

    # LOGS
    $logPatterns = @(
      'Connected to\s+([^\s,;:]+)',
      'Connected\s+to\s+([^\s,;:]+)',
      'Established VPN connection to ([^\s,;:]+)',
      'VPN connection to ([^\s,;:]+)',
      'Server:\s*([^\s,;:]+)',
      'Host:\s*([^\s,;:]+)',
      'd\.host=([^\s,;:]+)'
    )

    foreach ($b in $paths) {
      Get-ChildItem -Path $b -Include *.log,*.txt -Recurse -EA Ignore | ForEach-Object {
        $lines = Get-Content -LiteralPath $_.FullName -Tail 2000 -EA Ignore
        if (-not $lines) { return }
        foreach ($line in $lines) {
          foreach ($pat in $logPatterns) {
            $m = [regex]::Match($line, $pat)
            if ($m.Success) {
              $host = $m.Groups[1].Value.Trim()
              $ts   = $null
              if ($line -match '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') { $ts = $Matches[1] }
              elseif ($line -match '(\d{2}:\d{2}:\d{2})') { $ts = $Matches[1] }

              $acc.Add([pscustomobject]@{
                Source       = 'LogFile'
                File         = $_.FullName
                FriendlyName = $null
                Host         = $host
                ResolvedIP   = Try-ResolveHost $host
                LastSeen     = $ts
                Detail       = "Log match"
                MachineName  = $env:COMPUTERNAME
                Username     = $env:USERNAME
              })
            }
          }
          # IP solto
          $ipMatch = [regex]::Match($line, '((?:\d{1,3}\.){3}\d{1,3})')
          if ($ipMatch.Success) {
            $ip = $ipMatch.Groups[1].Value
            $acc.Add([pscustomobject]@{
              Source       = 'LogFile'
              File         = $_.FullName
              FriendlyName = $null
              Host         = $ip
              ResolvedIP   = $ip
              LastSeen     = $null
              Detail       = 'Log found IP'
              MachineName  = $env:COMPUTERNAME
              Username     = $env:USERNAME
            })
          }
        }
      }
    }

    return $acc
  }

  function Get-FromNetstatCisco {
    # Padrões de processos do AnyConnect
    $ciscoNames = @('vpnui','vpncli','vpnagent','acwebhelper')
    # `netstat -ano` funciona sem admin e traz PID/estado/endpoint remoto.
    $net = & netstat -ano | Where-Object { $_ -match 'TCP' -and $_ -match 'ESTABLISHED' }
    if (-not $net) { return @() }

    # Mapear PID -> Nome do processo
    $pidToName = @{}
    Get-Process -EA Ignore | ForEach-Object {
      $pidToName[[string]$_.Id] = $_.Name
    }

    $rows = @()
    foreach ($line in $net) {
      # Exemplo: TCP    10.0.0.5:54032    200.200.200.10:443   ESTABLISHED  1234
      $parts = $line -split '\s+' | ? { $_ -ne '' }
      if ($parts.Count -lt 5) { continue }
      $local  = $parts[1]
      $remote = $parts[2]
      $state  = $parts[3]
      $pid    = $parts[-1]

      $pname = $null
      if ($pidToName.ContainsKey([string]$pid)) { $pname = $pidToName[[string]$pid] }

      # filtra conexões cujo processo seja do AnyConnect (quando possível) OU
      # quando porta remota for 443/8443 (comum em gateways), para ampliar captura
      $remotePort = ($remote -split ':')[-1]
      $looksCisco = $false
      if ($pname) {
        foreach ($cn in $ciscoNames) {
          if ($pname -match [regex]::Escape($cn)) { $looksCisco = $true; break }
        }
      }
      if (-not $looksCisco -and ($remotePort -eq '443' -or $remotePort -eq '8443')) {
        # mantém como possível candidato
        $looksCisco = $true
      }
      if (-not $looksCisco) { continue }

      $remoteHost = ($remote -split ':')[0]

      $rows += [pscustomobject]@{
        Source       = 'Netstat'
        File         = $null
        FriendlyName = $null
        Host         = $remoteHost
        ResolvedIP   = $remoteHost
        LastSeen     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Detail       = "ESTABLISHED via PID $pid ($pname)"
        MachineName  = $env:COMPUTERNAME
        Username     = $env:USERNAME
      }
    }
    return $rows
  }

  $all = @()
  $all += Get-FromProfilesAndLogs
  $all += Get-FromNetstatCisco

  # Limpeza e dedupe (chave: Machine + Host + Source + File + Detail)
  $clean = $all | ? { $_.Host -and -not [string]::IsNullOrWhiteSpace($_.Host) } |
    Sort-Object MachineName, Host, Source, File, Detail -Unique

  if ($ReturnRaw) { return $clean }

  # retorno padrão (para execução local isolada)
  $clean
}

# --- Execução: local ou remota ---
$aggregate = New-Object System.Collections.Generic.List[object]

if ($ComputerName -and $ComputerName.Count -gt 0) {
  $sessParams = @{ }
  if ($Credential) { $sessParams.Credential = $Credential }

  foreach ($cn in $ComputerName) {
    try {
      $result = Invoke-Command -ComputerName $cn @sessParams -ScriptBlock $CoreScript -ArgumentList $true -EA Stop
      # anexa/computa MachineName de remoto (já vem preenchido do bloco)
      $aggregate.AddRange($result)
      Write-Host "✔ Coletado de $cn" -ForegroundColor Green
    } catch {
      Write-Warning "Falha ao coletar em $cn: $($_.Exception.Message)"
    }
  }
} else {
  # Local
  $local = & $CoreScript -ReturnRaw
  $aggregate.AddRange($local)
}

# --- Saídas ---
if (-not $aggregate -or $aggregate.Count -eq 0) {
  Write-Warning "Nenhum host encontrado (perfis/logs/netstat). Sugestões:
  - Peça ao colaborador para abrir o AnyConnect e conectar, depois rode novamente.
  - Caso perfis sejam entregues só via portal, pode não haver XML local.
  - Verifique se o antivírus/EDR bloqueia leitura dos diretórios de log."
  return
}

# Mostra no console (resumo)
$aggregate | Sort-Object MachineName, Host, Source | Format-Table -AutoSize `
  MachineName, Username, Host, ResolvedIP, LastSeen, Source, Detail

# CSV
$aggregate | Select-Object MachineName, Username, FriendlyName, Host, ResolvedIP, LastSeen, Source, File, Detail |
  Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV salvo em: $outCsv" -ForegroundColor Cyan

# HTML opcional
if ($Html) {
  $style = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 16px; }
h1 { font-size: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px 8px; font-size: 12px; }
th { background: #f4f6f8; text-align: left; }
tr:nth-child(even){ background: #fafafa; }
.badge { display:inline-block; padding:2px 6px; border-radius:12px; background:#e8eefc; border:1px solid #c8d6fb; font-size:11px; }
.small { color:#666; font-size:11px; }
</style>
"@

  $meta = @"
<h1>Cisco AnyConnect – Hosts detectados</h1>
<p class='small'>Gerado em $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
"@

  $htmlTable = $aggregate |
    Select-Object MachineName, Username, FriendlyName, Host, ResolvedIP, LastSeen, Source, File, Detail |
    ConvertTo-Html -PreContent $meta -Head $style

  $htmlTable | Out-File -FilePath $outHtml -Encoding UTF8
  Write-Host "HTML salvo em: $outHtml" -ForegroundColor Cyan
}

Write-Host "`nConcluído." -ForegroundColor Green

# ============================================================
#  CYBER ESSENTIALS - FIREWALL CHECK
#  Checks Windows Firewall is active and correctly configured
# ============================================================
#
#  HOW TO RUN THIS SCRIPT (step by step):
#
#  1. Press the Windows key on your keyboard
#  2. Type: PowerShell
#  3. RIGHT-click on "Windows PowerShell" in the results
#  4. Click "Run as administrator"
#  5. Click "Yes" if a blue box asks for permission
#  6. In the black/blue window, paste the following line
#     and press Enter:
#
#     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#
#  7. Then paste the rest of this script and press Enter
#
#  NOTE: This script is read-only. It checks your settings
#  but does not make any changes to your machine.
#
# ============================================================

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  CYBER ESSENTIALS - FIREWALL CHECK" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# --- Check 1: Firewall enabled on all profiles ---
Write-Host "CHECK 1: Windows Firewall profiles..." -ForegroundColor White

try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $allEnabled = $true

    foreach ($profile in $profiles) {
        if ($profile.Enabled -eq $true) {
            Write-Host "  [PASS] $($profile.Name) profile: Firewall ON" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $($profile.Name) profile: Firewall OFF" -ForegroundColor Red
            Write-Host "         Action needed: Go to Windows Security > Firewall & network protection" -ForegroundColor Yellow
            Write-Host "         Turn on the firewall for the $($profile.Name) network" -ForegroundColor Yellow
            $allEnabled = $false
        }
    }

    if ($allEnabled) {
        Write-Host ""
        Write-Host "  [PASS] Firewall is active on all network profiles" -ForegroundColor Green
    }

} catch {
    Write-Host "  [WARN] Could not retrieve firewall profile status" -ForegroundColor Yellow
    Write-Host "         Action needed: Check Windows Security > Firewall & network protection manually" -ForegroundColor Yellow
}

Write-Host ""

# --- Check 2: Default inbound action ---
Write-Host "CHECK 2: Default inbound connection policy..." -ForegroundColor White

try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($profile in $profiles) {
        if ($profile.DefaultInboundAction -eq "Block") {
            Write-Host "  [PASS] $($profile.Name) profile: Default inbound action is BLOCK" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $($profile.Name) profile: Default inbound action is ALLOW" -ForegroundColor Red
            Write-Host "         Action needed: Set default inbound action to Block for $($profile.Name) profile" -ForegroundColor Yellow
            Write-Host "         Run: Set-NetFirewallProfile -Profile $($profile.Name) -DefaultInboundAction Block" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "  [WARN] Could not check default inbound policy" -ForegroundColor Yellow
}

Write-Host ""

# --- Check 3: Risky inbound rules check ---
Write-Host "CHECK 3: Risky inbound firewall rules..." -ForegroundColor White

try {
    $riskyPorts = @(23, 3389, 5900, 21, 20, 69, 161, 162, 445, 135, 139)
    $riskyNames = @{
        23   = "Telnet (unencrypted remote access)"
        3389 = "RDP - Remote Desktop Protocol"
        5900 = "VNC - Virtual Network Computing"
        21   = "FTP (unencrypted file transfer)"
        20   = "FTP Data"
        69   = "TFTP (trivial file transfer)"
        161  = "SNMP"
        162  = "SNMP Trap"
        445  = "SMB - file sharing"
        135  = "RPC Endpoint Mapper"
        139  = "NetBIOS"
    }

    $inboundRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop
    $riskyFound = $false

    foreach ($rule in $inboundRules) {
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($portFilter -and $portFilter.LocalPort -ne "Any") {
            $ports = $portFilter.LocalPort -split ","
            foreach ($port in $ports) {
                $portNum = [int]($port.Trim()) 2>$null
                if ($riskyPorts -contains $portNum) {
                    Write-Host "  [WARN] Inbound rule allows port $portNum ($($riskyNames[$portNum]))" -ForegroundColor Yellow
                    Write-Host "         Rule name: $($rule.DisplayName)" -ForegroundColor Yellow
                    Write-Host "         Review whether this rule is necessary" -ForegroundColor Yellow
                    $riskyFound = $true
                }
            }
        }
    }

    if (-not $riskyFound) {
        Write-Host "  [PASS] No obviously risky inbound rules detected" -ForegroundColor Green
    }

} catch {
    Write-Host "  [WARN] Could not scan inbound firewall rules" -ForegroundColor Yellow
    Write-Host "         Action needed: Review inbound rules manually in Windows Defender Firewall" -ForegroundColor Yellow
}

Write-Host ""

# --- Check 4: Remote Desktop status ---
Write-Host "CHECK 4: Remote Desktop (RDP) status..." -ForegroundColor White

try {
    $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop

    if ($rdp.fDenyTSConnections -eq 1) {
        Write-Host "  [PASS] Remote Desktop is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Remote Desktop is ENABLED on this machine" -ForegroundColor Yellow
        Write-Host "         RDP on port 3389 is a common attack vector" -ForegroundColor Yellow
        Write-Host "         Action needed: Disable RDP if not required" -ForegroundColor Yellow
        Write-Host "         Go to: Settings > System > Remote Desktop > turn OFF" -ForegroundColor Yellow
        Write-Host "         If RDP is needed, ensure it is restricted by IP and uses MFA" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [WARN] Could not determine Remote Desktop status" -ForegroundColor Yellow
    Write-Host "         Action needed: Check Settings > System > Remote Desktop manually" -ForegroundColor Yellow
}

Write-Host ""

# --- Check 5: Windows Firewall logging ---
Write-Host "CHECK 5: Firewall logging..." -ForegroundColor White

try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $loggingEnabled = $false

    foreach ($profile in $profiles) {
        if ($profile.LogAllowed -eq "True" -or $profile.LogBlocked -eq "True") {
            Write-Host "  [PASS] $($profile.Name) profile: Logging is enabled" -ForegroundColor Green
            $loggingEnabled = $true
        } else {
            Write-Host "  [INFO] $($profile.Name) profile: Logging is not enabled" -ForegroundColor Gray
        }
    }

    if (-not $loggingEnabled) {
        Write-Host "  [WARN] Firewall logging is not enabled on any profile" -ForegroundColor Yellow
        Write-Host "         Logging is recommended for incident investigation" -ForegroundColor Yellow
        Write-Host "         Action needed: Enable via Windows Defender Firewall > Advanced Settings" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  [WARN] Could not check firewall logging status" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Cyber Essentials requires:" -ForegroundColor White
Write-Host "   - Firewall enabled on ALL network profiles (Domain, Private, Public)" -ForegroundColor White
Write-Host "   - Default inbound connections set to BLOCK" -ForegroundColor White
Write-Host "   - No unnecessary inbound rules exposing risky ports" -ForegroundColor White
Write-Host "   - Remote access services disabled unless explicitly needed" -ForegroundColor White
Write-Host ""
Write-Host "  If any check above shows [FAIL] or [WARN]," -ForegroundColor White
Write-Host "  address it before your Cyber Essentials assessment." -ForegroundColor White
Write-Host ""
Write-Host "  Need help? Contact Prestige Cyber Guard:" -ForegroundColor White
Write-Host "  hello@prestigecyberguard.co.uk" -ForegroundColor Cyan
Write-Host "  www.prestigecyberguard.co.uk" -ForegroundColor Cyan
Write-Host ""

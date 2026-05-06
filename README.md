# Cyber Essentials — Firewall Check

A free, beginner-friendly PowerShell script to check whether your Windows 
Firewall is correctly configured across all network profiles.

This is part of the **Prestige Cyber Guard** Cyber Essentials compliance 
series — practical tools to help UK businesses audit their security 
posture before assessment.

---

## Why this matters

Cyber Essentials requires that a firewall is active on every device, 
that inbound connections are blocked by default, and that unnecessary 
ports are not left open. Windows Firewall operates across three separate 
profiles — Domain, Private, and Public — and all three must be active.

A common gap is leaving Remote Desktop (RDP) enabled. Port 3389 is one 
of the most targeted ports on the internet and a leading cause of 
ransomware attacks. If it's not needed, it should be off.

This is assessed under the **Firewall** control — one of the five core 
Cyber Essentials requirements.

---

## What the script checks

| Check | What it looks for |
|---|---|
| ✅ Firewall profiles | Firewall enabled on Domain, Private, and Public profiles |
| ✅ Default inbound policy | Default action set to Block (not Allow) |
| ✅ Risky inbound rules | Open ports including Telnet, RDP, VNC, FTP, SMB |
| ✅ Remote Desktop | RDP enabled or disabled |
| ✅ Firewall logging | Whether logging is configured for incident investigation |

---

## How to run

### Step 1 — Open PowerShell as administrator

1. Press the **Windows key**
2. Type `PowerShell`
3. Right-click → **Run as administrator**

### Step 2 — Allow the script to run (temporary)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This resets automatically when you close the window.

### Step 3 — Paste and run the script

```powershell
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  CYBER ESSENTIALS - FIREWALL CHECK" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

$profiles = Get-NetFirewallProfile
foreach ($profile in $profiles) {
    if ($profile.Enabled) {
        Write-Host "[PASS] $($profile.Name) profile: Firewall ON" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $($profile.Name) profile: Firewall OFF" -ForegroundColor Red
    }
}

foreach ($profile in $profiles) {
    if ($profile.DefaultInboundAction -eq "Block") {
        Write-Host "[PASS] $($profile.Name): Default inbound is BLOCK" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $($profile.Name): Default inbound is ALLOW - change to Block" -ForegroundColor Red
    }
}

$riskyPorts = @(23,3389,5900,21,445,135,139)
$riskyNames = @{23="Telnet";3389="RDP";5900="VNC";21="FTP";445="SMB";135="RPC";139="NetBIOS"}
$rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True
$found = $false
foreach ($rule in $rules) {
    $pf = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    if ($pf -and $pf.LocalPort -ne "Any") {
        foreach ($port in ($pf.LocalPort -split ",")) {
            $p = [int]($port.Trim()) 2>$null
            if ($riskyPorts -contains $p) {
                Write-Host "[WARN] Port $p open ($($riskyNames[$p])) - $($rule.DisplayName)" -ForegroundColor Yellow
                $found = $true
            }
        }
    }
}
if (-not $found) { Write-Host "[PASS] No risky inbound rules detected" -ForegroundColor Green }

$rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
if ($rdp.fDenyTSConnections -eq 1) {
    Write-Host "[PASS] Remote Desktop is disabled" -ForegroundColor Green
} else {
    Write-Host "[WARN] Remote Desktop is ENABLED - disable if not required" -ForegroundColor Yellow
}

Write-Host "Need help? hello@prestigecyberguard.co.uk" -ForegroundColor Cyan
```

---

## What the results mean

| Result | Meaning |
|---|---|
| ✅ PASS | Meets the Cyber Essentials requirement |
| ⚠️ WARN | Needs reviewing before your assessment |
| ❌ FAIL | Direct gap — must be fixed before certification |

---

## Full guide

Read the full blog post with step-by-step instructions and Cyber 
Essentials context:

👉 https://www.prestigecyberguard.co.uk/blog

---

## About Prestige Cyber Guard

We help UK businesses achieve and maintain Cyber Essentials 
certification — making cybersecurity clear, practical, and affordable.

🌐 [prestigecyberguard.co.uk](https://www.prestigecyberguard.co.uk)  
📧 hello@prestigecyberguard.co.uk

---

## Part of a series

| Script | Control | Status |
|---|---|---|
| Privileged account check | User Access Control | ✅ Available |
| Malware protection check | Malware Protection | ✅ Available |
| Security update check | Security Updates | ✅ Available |
| Firewall check | Firewall | ✅ This repo |
| Secure configuration check | Secure Configuration | 🔜 Coming soon |

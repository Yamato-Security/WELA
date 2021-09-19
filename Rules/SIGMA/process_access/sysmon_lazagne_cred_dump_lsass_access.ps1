# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "CallTrace.*.*C:\Windows\SYSTEM32\ntdll.dll+.*" -and $_.message -match "CallTrace.*.*|C:\Windows\System32\KERNELBASE.dll+.*" -and $_.message -match "CallTrace.*.*_ctypes.pyd+.*" -and $_.message -match "CallTrace.*.*python27.dll+.*" -and $_.message -match "GrantedAccess.*0x1FFFFF") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_lazagne_cred_dump_lsass_access";
    $detectedMessage = "Detects LSASS process access by LaZagne for credential dumping.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "CallTrace.*.*C:\Windows\SYSTEM32\ntdll.dll+.*" -and $_.message -match "CallTrace.*.*|C:\Windows\System32\KERNELBASE.dll+.*" -and $_.message -match "CallTrace.*.*_ctypes.pyd+.*" -and $_.message -match "CallTrace.*.*python27.dll+.*" -and $_.message -match "GrantedAccess.*0x1FFFFF") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}

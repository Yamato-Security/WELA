# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "10") -and ((($_.ID -eq "10") -and (($_.message -match "CallTrace.*.*C:\Windows\SYSTEM32\ntdll.dll+.*" -and $_.message -match "CallTrace.*.*|C:\Windows\System32\KERNELBASE.dll+.*" -and $_.message -match "CallTrace.*.*|UNKNOWN(.*" -and $_.message -match "CallTrace.*.*).*") -or ($_.message -match "CallTrace.*.*UNKNOWN(.*" -and $_.message -match "CallTrace.*.*)|UNKNOWN(.*" -and $_.message -match "CallTrace.*.*)"))) -or (($_.ID -eq "10" -and $_.message -match "CallTrace.*.*UNKNOWN.*" -and ($_.message -match "0x1F0FFF" -or $_.message -match "0x1F1FFF" -or $_.message -match "0x143A" -or $_.message -match "0x1410" -or $_.message -match "0x1010" -or $_.message -match "0x1F2FFF" -or $_.message -match "0x1F3FFF" -or $_.message -match "0x1FFFFF")) -and  -not (($_.message -match "SourceImage.*.*\Windows\System32\sdiagnhost.exe"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_in_memory_assembly_execution";
    $detectedMessage = "Detects the access to processes by other suspicious processes which have reflectively loaded libraries in their memory space. An example is SilentTrinity";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "10") -and ((($_.ID -eq "10") -and (($_.message -match "CallTrace.*.*C:\Windows\SYSTEM32\ntdll.dll+.*" -and $_.message -match "CallTrace.*.*|C:\Windows\System32\KERNELBASE.dll+.*" -and $_.message -match "CallTrace.*.*|UNKNOWN(.*" -and $_.message -match "CallTrace.*.*).*") -or ($_.message -match "CallTrace.*.*UNKNOWN(.*" -and $_.message -match "CallTrace.*.*)|UNKNOWN(.*" -and $_.message -match "CallTrace.*.*)"))) -or (($_.ID -eq "10" -and $_.message -match "CallTrace.*.*UNKNOWN.*" -and ($_.message -match "0x1F0FFF" -or $_.message -match "0x1F1FFF" -or $_.message -match "0x143A" -or $_.message -match "0x1410" -or $_.message -match "0x1010" -or $_.message -match "0x1F2FFF" -or $_.message -match "0x1F3FFF" -or $_.message -match "0x1FFFFF")) -and -not (($_.message -match "SourceImage.*.*\Windows\System32\sdiagnhost.exe"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}

# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "10") -and ((($_.ID -eq "10") -and (($_.message -match "CallTrace.*.*C:\Windows\SYSTEM32\ntdll.dll+" -and $_.message -match "CallTrace.*.*|C:\Windows\System32\KERNELBASE.dll+" -and $_.message -match "CallTrace.*.*|UNKNOWN(" -and $_.message -match "CallTrace.*.*)") -or ($_.message -match "CallTrace.*.*UNKNOWN(" -and $_.message -match "CallTrace.*.*)|UNKNOWN(" -and $_.message -match "CallTrace.*.*)"))) -or (($_.ID -eq "10" -and $_.message -match "CallTrace.*.*UNKNOWN" -and ($_.message -match "0x1F0FFF" -or $_.message -match "0x1F1FFF" -or $_.message -match "0x143A" -or $_.message -match "0x1410" -or $_.message -match "0x1010" -or $_.message -match "0x1F2FFF" -or $_.message -match "0x1F3FFF" -or $_.message -match "0x1FFFFF")) -and  -not (($_.message -match "SourceImage.*.*\Windows\System32\sdiagnhost.exe"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_in_memory_assembly_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_in_memory_assembly_execution";
            $detectedMessage = "Detects the access to processes by other suspicious processes which have reflectively loaded libraries in their memory space. An example is SilentTrinity";
            $result = $event |  where { (($_.ID -eq "10") -and ((($_.ID -eq "10") -and (($_.message -match "CallTrace.*.*C:\\Windows\\SYSTEM32\\ntdll.dll+" -and $_.message -match "CallTrace.*.*|C:\\Windows\\System32\\KERNELBASE.dll+" -and $_.message -match "CallTrace.*.*|UNKNOWN\(" -and $_.message -match "CallTrace.*.*\)") -or ($_.message -match "CallTrace.*.*UNKNOWN\(" -and $_.message -match "CallTrace.*.*\)|UNKNOWN\(" -and $_.message -match "CallTrace.*.*\)"))) -or (($_.ID -eq "10" -and $_.message -match "CallTrace.*.*UNKNOWN" -and ($_.message -match "0x1F0FFF" -or $_.message -match "0x1F1FFF" -or $_.message -match "0x143A" -or $_.message -match "0x1410" -or $_.message -match "0x1010" -or $_.message -match "0x1F2FFF" -or $_.message -match "0x1F3FFF" -or $_.message -match "0x1FFFFF")) -and -not (($_.message -match "SourceImage.*.*\\Windows\\System32\\sdiagnhost.exe"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}

# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\csi.exe" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "OriginalFileName.*csi.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_use_of_csharp_console";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_use_of_csharp_console";
            $detectedMessage = "Detects the execution of CSharp interactive console by PowerShell";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\csi.exe" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "OriginalFileName.*csi.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}

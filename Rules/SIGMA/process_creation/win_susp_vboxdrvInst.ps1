# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\VBoxDrvInst.exe" -and $_.message -match "CommandLine.*.*driver" -and $_.message -match "CommandLine.*.*executeinf") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_vboxdrvInst";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_vboxdrvInst";
            $detectedMessage = "Detect VBoxDrvInst.exe run whith parameters allowing processing INF file. This allows to create values in the registry and install drivers.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\VBoxDrvInst.exe" -and $_.message -match "CommandLine.*.*driver" -and $_.message -match "CommandLine.*.*executeinf") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}

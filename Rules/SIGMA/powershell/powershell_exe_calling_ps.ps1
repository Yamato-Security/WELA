# Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and ($_.message -match "EngineVersion.*2." -or $_.message -match "EngineVersion.*4." -or $_.message -match "EngineVersion.*5.") -and $_.message -match "HostVersion.*3.") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_exe_calling_ps";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_exe_calling_ps";
            $detectedMessage = "Detects PowerShell called from an executable by the version mismatch method";
            $result = $event |  where { ($_.ID -eq "400" -and ($_.message -match "EngineVersion.*2." -or $_.message -match "EngineVersion.*4." -or $_.message -match "EngineVersion.*5.") -and $_.message -match "HostVersion.*3.") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

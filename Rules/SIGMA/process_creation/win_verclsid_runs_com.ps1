# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\verclsid.exe" -and $_.message -match "CommandLine.*.*/C" -and $_.message -match "CommandLine.*.*/S") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_verclsid_runs_com";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_verclsid_runs_com";
            $detectedMessage = "Detects when verclsid.exe is used to run COM object via GUID";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\verclsid.exe" -and $_.message -match "CommandLine.*.*/C" -and $_.message -match "CommandLine.*.*/S") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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

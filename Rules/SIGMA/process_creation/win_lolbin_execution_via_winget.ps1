# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*..*(?i)winget install (--m|-m).")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_lolbin_execution_via_winget";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_lolbin_execution_via_winget";
            $detectedMessage = "Adversaries can abuse winget to download payloads remotely and execute them without touching disk. Winget will be included by default in Windows 10 and is already available in Windows 10 insider programs. The manifest option enables you to install an application by passing in a YAML file directly to the client. Winget can be used to download and install exe's, msi, msix files later.";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*..*(?i)winget install (--m|-m).")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

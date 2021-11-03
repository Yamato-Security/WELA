# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Image.*.*wuauclt") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wuauclt_network_connection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_wuauclt_network_connection";
            $detectedMessage = "Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code and making a network connections. One could easily make the DLL spawn a new process and inject to it to proxy the network connection and bypass this rule.";
            $result = $event |  where { ($_.ID -eq "3" -and $_.message -match "Image.*.*wuauclt") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

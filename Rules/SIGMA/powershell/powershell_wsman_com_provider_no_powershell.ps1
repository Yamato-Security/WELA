# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.message -match "ProviderName=WSMan" -and  -not ($_.message -match "HostApplication=.*powershell")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_wsman_com_provider_no_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_wsman_com_provider_no_powershell";
            $detectedMessage = "Detects suspicious use of the WSMAN provider without PowerShell.exe as the host application.";
            $result = $event |  where { $_.message -match "ProviderName=WSMan"}
            if($result -ne $null) {
                $result = $result | where {-not ($_.message -match "HostApplication=.*powershell")} | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            }
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

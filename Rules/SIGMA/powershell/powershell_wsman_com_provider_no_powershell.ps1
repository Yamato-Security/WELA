# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.message -match ".*ProviderName=WSMan.*" -and  -not ($_.message -match ".*HostApplication=.*powershell.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_wsman_com_provider_no_powershell";
    $detectedMessage = "Detects suspicious use of the WSMAN provider without PowerShell.exe as the host application.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.message -match ".*ProviderName=WSMan.*" -and -not ($_.message -match ".*HostApplication=.*powershell.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}

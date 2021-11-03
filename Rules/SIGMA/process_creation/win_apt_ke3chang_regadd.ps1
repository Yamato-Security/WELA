# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force" -or $_.message -match "CommandLine.*.*-Property String -name Check_Associations -value" -or $_.message -match "CommandLine.*.*-Property DWORD -name IEHarden -value 0 -Force")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_ke3chang_regadd";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_ke3chang_regadd";
            $detectedMessage = "Detects Registry modifications performed by Ke3chang malware in campaigns running in 2019 and 2020";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force" -or $_.message -match "CommandLine.*.*-Property String -name Check_Associations -value" -or $_.message -match "CommandLine.*.*-Property DWORD -name IEHarden -value 0 -Force")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

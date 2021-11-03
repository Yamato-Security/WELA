# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmstp.exe" -and ($_.message -match "CommandLine.*.*/s" -or $_.message -match "CommandLine.*.*/au")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_uac_cmstp";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_uac_cmstp";
                    $detectedMessage = "Detect child processes of automatically elevated instances of Microsoft Connection Manager Profile Installer (cmstp.exe).";
                $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmstp.exe" -and ($_.message -match "CommandLine.*.*/s" -or $_.message -match "CommandLine.*.*/au")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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

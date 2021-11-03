# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "ImageLoaded.*.*\AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_pcre_net_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_pcre_net_load";
            $detectedMessage = "Detects processes loading modules related to PCRE.NET package";
            $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "ImageLoaded.*.*\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

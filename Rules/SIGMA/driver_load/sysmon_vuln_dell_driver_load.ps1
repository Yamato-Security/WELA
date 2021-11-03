# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "6") -and ($_.message -match "ImageLoaded.*.*\DBUtil_2_3.Sys" -or ($_.message -match "Hashes.*.*0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5" -or $_.message -match "Hashes.*.*c948ae14761095e4d76b55d9de86412258be7afd" -or $_.message -match "Hashes.*.*c996d7971c49252c582171d9380360f2" -or $_.message -match "Hashes.*.*ddbf5ecca5c8086afde1fb4f551e9e6400e94f4428fe7fb5559da5cffa654cc1" -or $_.message -match "Hashes.*.*10b30bdee43b3a2ec4aa63375577ade650269d25" -or $_.message -match "Hashes.*.*d2fd132ab7bbc6bbb87a84f026fa0244"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_vuln_dell_driver_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_vuln_dell_driver_load";
            $detectedMessage = "Detects the load of the vulnerable Dell BIOS update driver as reported in CVE-2021-21551";
            $result = $event |  where { (($_.ID -eq "6") -and ($_.message -match "ImageLoaded.*.*\\DBUtil_2_3.Sys" -or ($_.message -match "Hashes.*.*0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5" -or $_.message -match "Hashes.*.*c948ae14761095e4d76b55d9de86412258be7afd" -or $_.message -match "Hashes.*.*c996d7971c49252c582171d9380360f2" -or $_.message -match "Hashes.*.*ddbf5ecca5c8086afde1fb4f551e9e6400e94f4428fe7fb5559da5cffa654cc1" -or $_.message -match "Hashes.*.*10b30bdee43b3a2ec4aa63375577ade650269d25" -or $_.message -match "Hashes.*.*d2fd132ab7bbc6bbb87a84f026fa0244"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

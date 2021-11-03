# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* tcp 139" -or $_.message -match "CommandLine.*.* tcp 445" -or $_.message -match "CommandLine.*.* tcp 3389" -or $_.message -match "CommandLine.*.* tcp 5985" -or $_.message -match "CommandLine.*.* tcp 5986") -or ($_.message -match "CommandLine.*.* start " -and $_.message -match "CommandLine.*.*--all" -and $_.message -match "CommandLine.*.*--config" -and $_.message -match "CommandLine.*.*.yml") -or (($_.message -match "Image.*.*ngrok.exe") -and ($_.message -match "CommandLine.*.* tcp " -or $_.message -match "CommandLine.*.* http " -or $_.message -match "CommandLine.*.* authtoken ")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ngrok_pua";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_ngrok_pua";
            $detectedMessage = "Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available. Involved domains are bin.equinox.io for download and *.ngrok.io for connections.";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* tcp 139" -or $_.message -match "CommandLine.*.* tcp 445" -or $_.message -match "CommandLine.*.* tcp 3389" -or $_.message -match "CommandLine.*.* tcp 5985" -or $_.message -match "CommandLine.*.* tcp 5986") -or ($_.message -match "CommandLine.*.* start " -and $_.message -match "CommandLine.*.*--all" -and $_.message -match "CommandLine.*.*--config" -and $_.message -match "CommandLine.*.*.yml") -or (($_.message -match "Image.*.*ngrok.exe") -and ($_.message -match "CommandLine.*.* tcp " -or $_.message -match "CommandLine.*.* http " -or $_.message -match "CommandLine.*.* authtoken ")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

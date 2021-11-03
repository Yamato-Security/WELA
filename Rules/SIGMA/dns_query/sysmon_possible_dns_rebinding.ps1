# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "22" -and $_.message -match "QueryName.*" -and $_.message -match "QueryStatus.*0" -and ($_.message -match "QueryResults.*(::ffff:)?10." -or $_.message -match "QueryResults.*(::ffff:)?192.168." -or $_.message -match "QueryResults.*(::ffff:)?172.16." -or $_.message -match "QueryResults.*(::ffff:)?172.17." -or $_.message -match "QueryResults.*(::ffff:)?172.18." -or $_.message -match "QueryResults.*(::ffff:)?172.19." -or $_.message -match "QueryResults.*(::ffff:)?172.20." -or $_.message -match "QueryResults.*(::ffff:)?172.21." -or $_.message -match "QueryResults.*(::ffff:)?172.22." -or $_.message -match "QueryResults.*(::ffff:)?172.23." -or $_.message -match "QueryResults.*(::ffff:)?172.24." -or $_.message -match "QueryResults.*(::ffff:)?172.25." -or $_.message -match "QueryResults.*(::ffff:)?172.26." -or $_.message -match "QueryResults.*(::ffff:)?172.27." -or $_.message -match "QueryResults.*(::ffff:)?172.28." -or $_.message -match "QueryResults.*(::ffff:)?172.29." -or $_.message -match "QueryResults.*(::ffff:)?172.30." -or $_.message -match "QueryResults.*(::ffff:)?172.31." -or $_.message -match "QueryResults.*(::ffff:)?127.") -and ($_.ID -eq "22") -and ($_.message -match "QueryName.*" -and $_.message -match "QueryStatus.*0") -and  -not (($_.message -match "QueryResults.*(::ffff:)?10." -or $_.message -match "QueryResults.*(::ffff:)?192.168." -or $_.message -match "QueryResults.*(::ffff:)?172.16." -or $_.message -match "QueryResults.*(::ffff:)?172.17." -or $_.message -match "QueryResults.*(::ffff:)?172.18." -or $_.message -match "QueryResults.*(::ffff:)?172.19." -or $_.message -match "QueryResults.*(::ffff:)?172.20." -or $_.message -match "QueryResults.*(::ffff:)?172.21." -or $_.message -match "QueryResults.*(::ffff:)?172.22." -or $_.message -match "QueryResults.*(::ffff:)?172.23." -or $_.message -match "QueryResults.*(::ffff:)?172.24." -or $_.message -match "QueryResults.*(::ffff:)?172.25." -or $_.message -match "QueryResults.*(::ffff:)?172.26." -or $_.message -match "QueryResults.*(::ffff:)?172.27." -or $_.message -match "QueryResults.*(::ffff:)?172.28." -or $_.message -match "QueryResults.*(::ffff:)?172.29." -or $_.message -match "QueryResults.*(::ffff:)?172.30." -or $_.message -match "QueryResults.*(::ffff:)?172.31." -or $_.message -match "QueryResults.*(::ffff:)?127."))) }  | select ComputerName, QueryName | group ComputerName | foreach { [PSCustomObject]@{'ComputerName'=$_.name;'Count'=($_.group.QueryName | sort -u).count} }  | sort count -desc | where { $_.count -gt 3 }

function Add-Rule {

    $ruleName = "sysmon_possible_dns_rebinding";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_possible_dns_rebinding";
            $detectedMessage = "Detects several different DNS-answers by one domain with IPs from internal and external networks. Normally, DNS-answer contain TTL >100. (DNS-record will saved in host cache for a while TTL).";
            $result = $event |  where { ($_.ID -eq "22" -and $_.message -match "QueryName.*" -and $_.message -match "QueryStatus.*0" -and ($_.message -match "QueryResults.*(::ffff:)?10." -or $_.message -match "QueryResults.*(::ffff:)?192.168." -or $_.message -match "QueryResults.*(::ffff:)?172.16." -or $_.message -match "QueryResults.*(::ffff:)?172.17." -or $_.message -match "QueryResults.*(::ffff:)?172.18." -or $_.message -match "QueryResults.*(::ffff:)?172.19." -or $_.message -match "QueryResults.*(::ffff:)?172.20." -or $_.message -match "QueryResults.*(::ffff:)?172.21." -or $_.message -match "QueryResults.*(::ffff:)?172.22." -or $_.message -match "QueryResults.*(::ffff:)?172.23." -or $_.message -match "QueryResults.*(::ffff:)?172.24." -or $_.message -match "QueryResults.*(::ffff:)?172.25." -or $_.message -match "QueryResults.*(::ffff:)?172.26." -or $_.message -match "QueryResults.*(::ffff:)?172.27." -or $_.message -match "QueryResults.*(::ffff:)?172.28." -or $_.message -match "QueryResults.*(::ffff:)?172.29." -or $_.message -match "QueryResults.*(::ffff:)?172.30." -or $_.message -match "QueryResults.*(::ffff:)?172.31." -or $_.message -match "QueryResults.*(::ffff:)?127.") -and ($_.ID -eq "22") -and ($_.message -match "QueryName.*" -and $_.message -match "QueryStatus.*0") -and -not (($_.message -match "QueryResults.*(::ffff:)?10." -or $_.message -match "QueryResults.*(::ffff:)?192.168." -or $_.message -match "QueryResults.*(::ffff:)?172.16." -or $_.message -match "QueryResults.*(::ffff:)?172.17." -or $_.message -match "QueryResults.*(::ffff:)?172.18." -or $_.message -match "QueryResults.*(::ffff:)?172.19." -or $_.message -match "QueryResults.*(::ffff:)?172.20." -or $_.message -match "QueryResults.*(::ffff:)?172.21." -or $_.message -match "QueryResults.*(::ffff:)?172.22." -or $_.message -match "QueryResults.*(::ffff:)?172.23." -or $_.message -match "QueryResults.*(::ffff:)?172.24." -or $_.message -match "QueryResults.*(::ffff:)?172.25." -or $_.message -match "QueryResults.*(::ffff:)?172.26." -or $_.message -match "QueryResults.*(::ffff:)?172.27." -or $_.message -match "QueryResults.*(::ffff:)?172.28." -or $_.message -match "QueryResults.*(::ffff:)?172.29." -or $_.message -match "QueryResults.*(::ffff:)?172.30." -or $_.message -match "QueryResults.*(::ffff:)?172.31." -or $_.message -match "QueryResults.*(::ffff:)?127."))) } | select ComputerName, QueryName | group ComputerName | foreach { [PSCustomObject]@{'ComputerName' = $_.name; 'Count' = ($_.group.QueryName | sort -u).count } } | sort count -desc | where { $_.count -gt 3 };
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

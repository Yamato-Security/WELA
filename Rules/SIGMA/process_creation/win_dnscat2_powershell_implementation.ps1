# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\powershell.exe" -and $_.message -match "Image.*.*\nslookup.exe" -and $_.message -match "CommandLine.*.*\nslookup.exe") }  | select ParentImage, Image | group ParentImage | foreach { [PSCustomObject]@{'ParentImage'=$_.name;'Count'=($_.group.Image | sort -u).count} }  | sort count -desc | where { $_.count -gt 100 }

function Add-Rule {

    $ruleName = "win_dnscat2_powershell_implementation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_dnscat2_powershell_implementation";
            $detectedMessage = "The PowerShell implementation of DNSCat2 calls nslookup to craft queries. Counting nslookup processes spawned by PowerShell will show hundreds or thousands of instances if PS DNSCat2 is active locally.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\nslookup.exe" -and $_.message -match "CommandLine.*.*\\nslookup.exe") } | select ParentImage, Image | group ParentImage | foreach { [PSCustomObject]@{'ParentImage' = $_.name; 'Count' = ($_.group.Image | sort -u).count } } | sort count -desc | where { $_.count -gt 100 };
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

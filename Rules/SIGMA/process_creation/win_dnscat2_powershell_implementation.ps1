# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\powershell.exe" -and $_.message -match "Image.*.*\nslookup.exe" -and $_.message -match "CommandLine.*.*\nslookup.exe") }  | select ParentImage, Image | group ParentImage | foreach { [PSCustomObject]@{'ParentImage'=$_.name;'Count'=($_.group.Image | sort -u).count} }  | sort count -desc | where { $_.count -gt 100 }

function Add-Rule {

    $ruleName = "win_dnscat2_powershell_implementation";
    $detectedMessage = "The PowerShell implementation of DNSCat2 calls nslookup to craft queries. Counting nslookup processes spawned by PowerShell will show hundreds or thousands of instances if PS DNSCat2 is active locally.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\nslookup.exe" -and $_.message -match "CommandLine.*.*\\nslookup.exe") } | select ParentImage, Image | group ParentImage | foreach { [PSCustomObject]@{'ParentImage'=$_.name;'Count'=($_.group.Image | sort -u).count} } | sort count -desc | where { $_.count -gt 100 };
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\Bloodhound.exe" -or $_.message -match "Image.*.*\SharpHound.exe") -or ($_.message -match "CommandLine.*.* -CollectionMethod All " -or $_.message -match "CommandLine.*.*.exe -c All -d " -or $_.message -match "CommandLine.*.*Invoke-Bloodhound" -or $_.message -match "CommandLine.*.*Get-BloodHoundData") -or ($_.message -match "CommandLine.*.* -JsonFolder " -and $_.message -match "CommandLine.*.* -ZipFileName ") -or ($_.message -match "CommandLine.*.* DCOnly " -and $_.message -match "CommandLine.*.* --NoSaveCache "))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hack_bloodhound";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hack_bloodhound";
            $detectedMessage = "Detects command line parameters used by Bloodhound and Sharphound hack tools";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\Bloodhound.exe" -or $_.message -match "Image.*.*\\SharpHound.exe") -or ($_.message -match "CommandLine.*.* -CollectionMethod All " -or $_.message -match "CommandLine.*.*.exe -c All -d " -or $_.message -match "CommandLine.*.*Invoke-Bloodhound" -or $_.message -match "CommandLine.*.*Get-BloodHoundData") -or ($_.message -match "CommandLine.*.* -JsonFolder " -and $_.message -match "CommandLine.*.* -ZipFileName ") -or ($_.message -match "CommandLine.*.* DCOnly " -and $_.message -match "CommandLine.*.* --NoSaveCache "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

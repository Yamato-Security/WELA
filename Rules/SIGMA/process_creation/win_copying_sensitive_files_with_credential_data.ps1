# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\esentutl.exe" -and ($_.message -match "CommandLine.*.*vss" -or $_.message -match "CommandLine.*.* /m " -or $_.message -match "CommandLine.*.* /y ")) -or ($_.message -match "CommandLine.*.*\windows\ntds\ntds.dit" -or $_.message -match "CommandLine.*.*\config\sam" -or $_.message -match "CommandLine.*.*\config\security" -or $_.message -match "CommandLine.*.*\config\system " -or $_.message -match "CommandLine.*.*\repair\sam" -or $_.message -match "CommandLine.*.*\repair\system" -or $_.message -match "CommandLine.*.*\repair\security" -or $_.message -match "CommandLine.*.*\config\RegBack\sam" -or $_.message -match "CommandLine.*.*\config\RegBack\system" -or $_.message -match "CommandLine.*.*\config\RegBack\security"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_copying_sensitive_files_with_credential_data";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_copying_sensitive_files_with_credential_data";
            $detectedMessage = "Files with well-known filenames (sensitive files with credential data) copying";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\esentutl.exe" -and ($_.message -match "CommandLine.*.*vss" -or $_.message -match "CommandLine.*.* /m " -or $_.message -match "CommandLine.*.* /y ")) -or ($_.message -match "CommandLine.*.*\\windows\\ntds\\ntds.dit" -or $_.message -match "CommandLine.*.*\\config\\sam" -or $_.message -match "CommandLine.*.*\\config\\security" -or $_.message -match "CommandLine.*.*\\config\\system " -or $_.message -match "CommandLine.*.*\\repair\\sam" -or $_.message -match "CommandLine.*.*\\repair\\system" -or $_.message -match "CommandLine.*.*\\repair\\security" -or $_.message -match "CommandLine.*.*\\config\\RegBack\\sam" -or $_.message -match "CommandLine.*.*\\config\\RegBack\\system" -or $_.message -match "CommandLine.*.*\\config\\RegBack\\security"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

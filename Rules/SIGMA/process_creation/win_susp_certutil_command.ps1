# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -decode " -or $_.message -match "CommandLine.*.* -decodehex " -or $_.message -match "CommandLine.*.* -urlcache " -or $_.message -match "CommandLine.*.* -verifyctl " -or $_.message -match "CommandLine.*.* -encode " -or $_.message -match "CommandLine.*.* /decode " -or $_.message -match "CommandLine.*.* /decodehex " -or $_.message -match "CommandLine.*.* /urlcache " -or $_.message -match "CommandLine.*.* /verifyctl " -or $_.message -match "CommandLine.*.* /encode ") -or ($_.message -match "Image.*.*\\certutil.exe" -and ($_.message -match "CommandLine.*.*URL" -or $_.message -match "CommandLine.*.*ping")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_certutil_command";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_certutil_command";
            $detectedMessage = "Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -decode " -or $_.message -match "CommandLine.*.* -decodehex " -or $_.message -match "CommandLine.*.* -urlcache " -or $_.message -match "CommandLine.*.* -verifyctl " -or $_.message -match "CommandLine.*.* -encode " -or $_.message -match "CommandLine.*.* /decode " -or $_.message -match "CommandLine.*.* /decodehex " -or $_.message -match "CommandLine.*.* /urlcache " -or $_.message -match "CommandLine.*.* /verifyctl " -or $_.message -match "CommandLine.*.* /encode ") -or ($_.message -match "Image.*.*\\certutil.exe" -and ($_.message -match "CommandLine.*.*URL" -or $_.message -match "CommandLine.*.*ping")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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

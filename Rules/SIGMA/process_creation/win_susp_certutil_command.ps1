# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -decode .*" -or $_.message -match "CommandLine.*.* -decodehex .*" -or $_.message -match "CommandLine.*.* -urlcache .*" -or $_.message -match "CommandLine.*.* -verifyctl .*" -or $_.message -match "CommandLine.*.* -encode .*" -or $_.message -match "CommandLine.*.* /decode .*" -or $_.message -match "CommandLine.*.* /decodehex .*" -or $_.message -match "CommandLine.*.* /urlcache .*" -or $_.message -match "CommandLine.*.* /verifyctl .*" -or $_.message -match "CommandLine.*.* /encode .*") -or ($_.message -match "Image.*.*\\certutil.exe" -and ($_.message -match "CommandLine.*.*URL.*" -or $_.message -match "CommandLine.*.*ping.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_certutil_command";
    $detectedMessage = "Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -decode .*" -or $_.message -match "CommandLine.*.* -decodehex .*" -or $_.message -match "CommandLine.*.* -urlcache .*" -or $_.message -match "CommandLine.*.* -verifyctl .*" -or $_.message -match "CommandLine.*.* -encode .*" -or $_.message -match "CommandLine.*.* /decode .*" -or $_.message -match "CommandLine.*.* /decodehex .*" -or $_.message -match "CommandLine.*.* /urlcache .*" -or $_.message -match "CommandLine.*.* /verifyctl .*" -or $_.message -match "CommandLine.*.* /encode .*") -or ($_.message -match "Image.*.*\\certutil.exe" -and ($_.message -match "CommandLine.*.*URL.*" -or $_.message -match "CommandLine.*.*ping.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

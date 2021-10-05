# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*dir .*" -or $_.message -match "CommandLine.*.*findstr .*") -and ($_.message -match "CommandLine.*.*.key.*" -or $_.message -match "CommandLine.*.*.pgp.*" -or $_.message -match "CommandLine.*.*.gpg.*" -or $_.message -match "CommandLine.*.*.ppk.*" -or $_.message -match "CommandLine.*.*.p12.*" -or $_.message -match "CommandLine.*.*.pem.*" -or $_.message -match "CommandLine.*.*.pfx.*" -or $_.message -match "CommandLine.*.*.cer.*" -or $_.message -match "CommandLine.*.*.p7b.*" -or $_.message -match "CommandLine.*.*.asc.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_discover_private_keys";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_discover_private_keys";
            $detectedMessage = "Adversaries may search for private key certificate files on compromised systems for insecurely stored credential";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*dir .*" -or $_.message -match "CommandLine.*.*findstr .*") -and ($_.message -match "CommandLine.*.*.key.*" -or $_.message -match "CommandLine.*.*.pgp.*" -or $_.message -match "CommandLine.*.*.gpg.*" -or $_.message -match "CommandLine.*.*.ppk.*" -or $_.message -match "CommandLine.*.*.p12.*" -or $_.message -match "CommandLine.*.*.pem.*" -or $_.message -match "CommandLine.*.*.pfx.*" -or $_.message -match "CommandLine.*.*.cer.*" -or $_.message -match "CommandLine.*.*.p7b.*" -or $_.message -match "CommandLine.*.*.asc.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

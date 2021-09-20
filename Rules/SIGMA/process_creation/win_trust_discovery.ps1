# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\nltest.exe" -and ($_.message -match "CommandLine.*.*domain_trusts.*" -or $_.message -match "CommandLine.*.*all_trusts.*" -or $_.message -match "CommandLine.*.*/dclist.*")) -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*trustedDomain.*") -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*-filter.*" -and $_.message -match "CommandLine.*.*trustedDomain.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_trust_discovery";
    $detectedMessage = "Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\nltest.exe" -and ($_.message -match "CommandLine.*.*domain_trusts.*" -or $_.message -match "CommandLine.*.*all_trusts.*" -or $_.message -match "CommandLine.*.*/dclist.*")) -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*trustedDomain.*") -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*-filter.*" -and $_.message -match "CommandLine.*.*trustedDomain.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

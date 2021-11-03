# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\nltest.exe" -and ($_.message -match "CommandLine.*.*domain_trusts" -or $_.message -match "CommandLine.*.*all_trusts" -or $_.message -match "CommandLine.*.*/dclist")) -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*trustedDomain") -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*-filter" -and $_.message -match "CommandLine.*.*trustedDomain"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_trust_discovery";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_trust_discovery";
            $detectedMessage = "Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts.";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\nltest.exe" -and ($_.message -match "CommandLine.*.*domain_trusts" -or $_.message -match "CommandLine.*.*all_trusts" -or $_.message -match "CommandLine.*.*/dclist")) -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*trustedDomain") -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*-filter" -and $_.message -match "CommandLine.*.*trustedDomain"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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

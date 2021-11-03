# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*domainlist" -or $_.message -match "CommandLine.*.*trustdmp" -or $_.message -match "CommandLine.*.*dcmodes" -or $_.message -match "CommandLine.*.*adinfo" -or $_.message -match "CommandLine.*.* dclist " -or $_.message -match "CommandLine.*.*computer_pwdnotreqd" -or $_.message -match "CommandLine.*.*objectcategory=" -or $_.message -match "CommandLine.*.*-subnets -f" -or $_.message -match "CommandLine.*.*name="Domain Admins"" -or $_.message -match "CommandLine.*.*-sc u:" -or $_.message -match "CommandLine.*.*domainncs" -or $_.message -match "CommandLine.*.*dompol" -or $_.message -match "CommandLine.*.* oudmp " -or $_.message -match "CommandLine.*.*subnetdmp" -or $_.message -match "CommandLine.*.*gpodmp" -or $_.message -match "CommandLine.*.*fspdmp" -or $_.message -match "CommandLine.*.*users_noexpire" -or $_.message -match "CommandLine.*.*computers_active")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_ad_find_discovery";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_ad_find_discovery";
            $detectedMessage = "AdFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*domainlist" -or $_.message -match "CommandLine.*.*trustdmp" -or $_.message -match "CommandLine.*.*dcmodes" -or $_.message -match "CommandLine.*.*adinfo" -or $_.message -match "CommandLine.*.* dclist " -or $_.message -match "CommandLine.*.*computer_pwdnotreqd" -or $_.message -match "CommandLine.*.*objectcategory=" -or $_.message -match "CommandLine.*.*-subnets -f" -or $_.message -match "CommandLine.*.*name=""Domain Admins""" -or $_.message -match "CommandLine.*.*-sc u:" -or $_.message -match "CommandLine.*.*domainncs" -or $_.message -match "CommandLine.*.*dompol" -or $_.message -match "CommandLine.*.* oudmp " -or $_.message -match "CommandLine.*.*subnetdmp" -or $_.message -match "CommandLine.*.*gpodmp" -or $_.message -match "CommandLine.*.*fspdmp" -or $_.message -match "CommandLine.*.*users_noexpire" -or $_.message -match "CommandLine.*.*computers_active")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

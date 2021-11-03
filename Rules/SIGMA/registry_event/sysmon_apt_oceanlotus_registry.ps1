# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "HKCR\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model") -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\Application" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\DefaultIcon" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\Application" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\DefaultIcon" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\Application" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\DefaultIcon")) -or (($_.message -match "TargetObject.*HKU\\") -and ($_.message -match "TargetObject.*.*_Classes\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\" -or $_.message -match "TargetObject.*.*_Classes\\AppX3bbba44c6cae4d9695755183472171e2\\" -or $_.message -match "TargetObject.*.*_Classes\\CLSID\\{E3517E26-8E93-458D-A6DF-8030BC80528B}\\" -or $_.message -match "TargetObject.*.*_Classes\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_apt_oceanlotus_registry";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_apt_oceanlotus_registry";
            $detectedMessage = "Detects registry keys created in OceanLotus (also known as APT32) attacks";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "HKCR\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model") -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\Application" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\DefaultIcon" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\Application" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\DefaultIcon" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\Application" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\DefaultIcon")) -or (($_.message -match "TargetObject.*HKU\\") -and ($_.message -match "TargetObject.*.*_Classes\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\" -or $_.message -match "TargetObject.*.*_Classes\\AppX3bbba44c6cae4d9695755183472171e2\\" -or $_.message -match "TargetObject.*.*_Classes\\CLSID\\{E3517E26-8E93-458D-A6DF-8030BC80528B}\\" -or $_.message -match "TargetObject.*.*_Classes\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

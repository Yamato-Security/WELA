# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and (((($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\inetpub\wwwroot\.*" -and ($_.message -match "TargetFilename.*.*.asp.*" -or $_.message -match "TargetFilename.*.*.ashx.*" -or $_.message -match "TargetFilename.*.*.ph.*")) -and  -not (($_.message -match "TargetFilename.*.*\AppData\Local\Temp\.*" -or $_.message -match "TargetFilename.*.*\Windows\Temp\.*"))) -or (($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\www\.*" -or $_.message -match "TargetFilename.*.*\htdocs\.*" -or $_.message -match "TargetFilename.*.*\html\.*") -and $_.message -match "TargetFilename.*.*.ph.*") -and  -not (($_.message -match "TargetFilename.*.*\AppData\Local\Temp\.*" -or $_.message -match "TargetFilename.*.*\Windows\Temp\.*")))) -or (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*.jsp" -or ($_.message -match "TargetFilename.*.*\cgi-bin\.*" -and $_.message -match "TargetFilename.*.*.pl.*")) -and  -not (($_.message -match "TargetFilename.*.*\AppData\Local\Temp\.*" -or $_.message -match "TargetFilename.*.*\Windows\Temp\.*"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_webshell_creation_detect";
    $detectedMessage = "Possible webshell file creation on a static web site";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "11") -and (((($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\\inetpub\\wwwroot\\.*" -and ($_.message -match "TargetFilename.*.*.asp.*" -or $_.message -match "TargetFilename.*.*.ashx.*" -or $_.message -match "TargetFilename.*.*.ph.*")) -and -not (($_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\.*" -or $_.message -match "TargetFilename.*.*\\Windows\\Temp\\.*"))) -or (($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\\www\\.*" -or $_.message -match "TargetFilename.*.*\\htdocs\\.*" -or $_.message -match "TargetFilename.*.*\\html\\.*") -and $_.message -match "TargetFilename.*.*.ph.*") -and -not (($_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\.*" -or $_.message -match "TargetFilename.*.*\\Windows\\Temp\\.*")))) -or (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*.jsp" -or ($_.message -match "TargetFilename.*.*\\cgi-bin\\.*" -and $_.message -match "TargetFilename.*.*.pl.*")) -and -not (($_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\.*" -or $_.message -match "TargetFilename.*.*\\Windows\\Temp\\.*"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

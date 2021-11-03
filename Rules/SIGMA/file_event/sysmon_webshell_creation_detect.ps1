# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and (((($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\inetpub\wwwroot\" -and ($_.message -match "TargetFilename.*.*.asp" -or $_.message -match "TargetFilename.*.*.ashx" -or $_.message -match "TargetFilename.*.*.ph")) -and  -not (($_.message -match "TargetFilename.*.*\AppData\Local\Temp\" -or $_.message -match "TargetFilename.*.*\Windows\Temp\"))) -or (($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\www\" -or $_.message -match "TargetFilename.*.*\htdocs\" -or $_.message -match "TargetFilename.*.*\html\") -and $_.message -match "TargetFilename.*.*.ph") -and  -not (($_.message -match "TargetFilename.*.*\AppData\Local\Temp\" -or $_.message -match "TargetFilename.*.*\Windows\Temp\")))) -or (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*.jsp" -or ($_.message -match "TargetFilename.*.*\cgi-bin\" -and $_.message -match "TargetFilename.*.*.pl")) -and  -not (($_.message -match "TargetFilename.*.*\AppData\Local\Temp\" -or $_.message -match "TargetFilename.*.*\Windows\Temp\"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_webshell_creation_detect";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_webshell_creation_detect";
            $detectedMessage = "Possible webshell file creation on a static web site";
            $result = $event |  where { (($_.ID -eq "11") -and (((($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\\inetpub\\wwwroot\\" -and ($_.message -match "TargetFilename.*.*.asp" -or $_.message -match "TargetFilename.*.*.ashx" -or $_.message -match "TargetFilename.*.*.ph")) -and -not (($_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\" -or $_.message -match "TargetFilename.*.*\\Windows\\Temp\\"))) -or (($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\\www\\" -or $_.message -match "TargetFilename.*.*\\htdocs\\" -or $_.message -match "TargetFilename.*.*\\html\\") -and $_.message -match "TargetFilename.*.*.ph") -and -not (($_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\" -or $_.message -match "TargetFilename.*.*\\Windows\\Temp\\")))) -or (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*.jsp" -or ($_.message -match "TargetFilename.*.*\\cgi-bin\\" -and $_.message -match "TargetFilename.*.*.pl")) -and -not (($_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\" -or $_.message -match "TargetFilename.*.*\\Windows\\Temp\\"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

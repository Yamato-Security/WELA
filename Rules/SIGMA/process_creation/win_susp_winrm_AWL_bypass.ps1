# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*winrm" -and ($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*format:pretty" -or $_.message -match "CommandLine.*.*format:\"pretty\"" -or $_.message -match "CommandLine.*.*format:\"text\"" -or $_.message -match "CommandLine.*.*format:text") -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*WsmPty.xsl" -or $_.message -match "TargetFilename.*.*WsmTxt.xsl") -and -not (($_.message -match "TargetFilename.*C:\\Windows\\System32\\" -or $_.message -match "TargetFilename.*C:\\Windows\\SysWOW64\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_susp_winrm_AWL_bypass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_winrm_AWL_bypass";
            $detectedMessage = "Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*winrm" -and ($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*format:pretty" -or $_.message -match "CommandLine.*.*format:""pretty""" -or $_.message -match "CommandLine.*.*format:""text""" -or $_.message -match "CommandLine.*.*format:text") -and -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*WsmPty.xsl" -or $_.message -match "TargetFilename.*.*WsmTxt.xsl") -and -not (($_.message -match "TargetFilename.*C:\\Windows\\System32\\" -or $_.message -match "TargetFilename.*C:\\Windows\\SysWOW64\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
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

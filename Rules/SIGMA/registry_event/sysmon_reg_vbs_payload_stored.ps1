# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Windows\\CurrentVersion" -and ($_.message -match "Details.*.*vbscript" -or $_.message -match "Details.*.*jscript" -or $_.message -match "Details.*.*mshtml" -or $_.message -match "Details.*.*mshtml," -or $_.message -match "Details.*.*mshtml " -or $_.message -match "Details.*.*RunHTMLApplication" -or $_.message -match "Details.*.*Execute(" -or $_.message -match "Details.*.*CreateObject" -or $_.message -match "Details.*.*RegRead" -or $_.message -match "Details.*.*window.close")) -and  -not ($_.message -match "TargetObject.*.*Software\\Microsoft\\Windows\\CurrentVersion\\Run")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_reg_vbs_payload_stored";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_reg_vbs_payload_stored";
            $detectedMessage = "Detects VBScript content stored into registry keys as seen being used by UNC2452 group";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Windows\\CurrentVersion" -and ($_.message -match "Details.*.*vbscript" -or $_.message -match "Details.*.*jscript" -or $_.message -match "Details.*.*mshtml" -or $_.message -match "Details.*.*mshtml," -or $_.message -match "Details.*.*mshtml " -or $_.message -match "Details.*.*RunHTMLApplication" -or $_.message -match "Details.*.*Execute(" -or $_.message -match "Details.*.*CreateObject" -or $_.message -match "Details.*.*RegRead" -or $_.message -match "Details.*.*window.close")) -and -not ($_.message -match "TargetObject.*.*Software\\Microsoft\\Windows\\CurrentVersion\\Run")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

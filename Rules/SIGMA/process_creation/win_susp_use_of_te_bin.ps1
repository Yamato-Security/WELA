# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\te.exe" -or $_.message -match "ParentImage.*.*\\te.exe" -or $_.message -match "OriginalFileName.*\\te.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_use_of_te_bin";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_use_of_te_bin";
            $detectedMessage = "Windows Test Authoring and Execution Framework (TAEF) framework allows you to run automation by executing tests files written on different languages (C, C#, Microsoft COM Scripting interfaces). Adversaries may execute malicious code (such as WSC file with VBScript, dll and so on) directly by running te.exe";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\te.exe" -or $_.message -match "ParentImage.*.*\\te.exe" -or $_.message -match "OriginalFileName.*\\te.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

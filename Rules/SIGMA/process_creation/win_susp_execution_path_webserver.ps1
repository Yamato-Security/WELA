# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\wwwroot\\.*" -or $_.message -match "Image.*.*\\wmpub\\.*" -or $_.message -match "Image.*.*\\htdocs\\.*") -and  -not (($_.message -match "Image.*.*bin\\.*" -or $_.message -match "Image.*.*\\Tools\\.*" -or $_.message -match "Image.*.*\\SMSComponent\\.*") -and ($_.message -match "ParentImage.*.*\\services.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_execution_path_webserver";
    $detectedMessage = "Detects a suspicious program execution in a web service root folder (filter out false positives)";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\wwwroot\\.*" -or $_.message -match "Image.*.*\\wmpub\\.*" -or $_.message -match "Image.*.*\\htdocs\\.*") -and -not (($_.message -match "Image.*.*bin\\.*" -or $_.message -match "Image.*.*\\Tools\\.*" -or $_.message -match "Image.*.*\\SMSComponent\\.*") -and ($_.message -match "ParentImage.*.*\\services.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

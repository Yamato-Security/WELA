# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\protocolhandler.exe" -and $_.message -match "CommandLine.*.*"ms-word.*" -and $_.message -match "CommandLine.*.*.docx".*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_protocolhandler_suspicious_file";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_protocolhandler_suspicious_file";
            $detectedMessage = "Emulates attack via documents through protocol handler in Microsoft Office. On successful execution you should see Microsoft Word launch a blank file.";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\protocolhandler.exe" -and $_.message -match "CommandLine.*.*.ms-word.*" -and $_.message -match "CommandLine.*.*.docx.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}

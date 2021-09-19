# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\wmic.exe" -and $_.message -match "CommandLine.*.*/format.*") -or $_.message -match "Image.*.*\msxsl.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_xsl_script_processing";
    $detectedMessage = "Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. Rule detects when adversaries";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\wmic.exe" -and $_.message -match "CommandLine.*.*/format.*") -or $_.message -match "Image.*.*\msxsl.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}

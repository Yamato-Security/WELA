# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.*/format") -or $_.message -match "Image.*.*\\msxsl.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_xsl_script_processing";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_xsl_script_processing";
            $detectedMessage = "Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. Rule detects when adversaries";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.*/format") -or $_.message -match "Image.*.*\\msxsl.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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

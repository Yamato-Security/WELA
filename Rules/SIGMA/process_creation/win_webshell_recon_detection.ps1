# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\apache" -or $_.message -match "ParentImage.*.*\\tomcat") -or ($_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe")) -and (($_.message -match "Image.*.*\\cmd.exe") -and ($_.message -match "CommandLine.*.*perl --help" -or $_.message -match "CommandLine.*.*python --help" -or $_.message -match "CommandLine.*.*wget --help" -or $_.message -match "CommandLine.*.*perl -h"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_webshell_recon_detection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_webshell_recon_detection";
            $detectedMessage = "Looking for processes spawned by web server components that indicate reconnaissance by popular public domain webshells for whether perl, python or wget are installed.";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\apache" -or $_.message -match "ParentImage.*.*\\tomcat") -or ($_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe")) -and (($_.message -match "Image.*.*\\cmd.exe") -and ($_.message -match "CommandLine.*.*perl --help" -or $_.message -match "CommandLine.*.*python --help" -or $_.message -match "CommandLine.*.*wget --help" -or $_.message -match "CommandLine.*.*perl -h"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

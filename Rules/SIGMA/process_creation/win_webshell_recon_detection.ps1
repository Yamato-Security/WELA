# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\apache.*" -or $_.message -match "ParentImage.*.*\tomcat.*") -or ($_.message -match "ParentImage.*.*\w3wp.exe" -or $_.message -match "ParentImage.*.*\php-cgi.exe" -or $_.message -match "ParentImage.*.*\nginx.exe" -or $_.message -match "ParentImage.*.*\httpd.exe")) -and (($_.message -match "Image.*.*\cmd.exe") -and ($_.message -match "CommandLine.*.*perl --help.*" -or $_.message -match "CommandLine.*.*python --help.*" -or $_.message -match "CommandLine.*.*wget --help.*" -or $_.message -match "CommandLine.*.*perl -h.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_webshell_recon_detection";
    $detectedMessage = "Looking for processes spawned by web server components that indicate reconnaissance by popular public domain webshells for whether perl, python or wget are installed.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\apache.*" -or $_.message -match "ParentImage.*.*\tomcat.*") -or ($_.message -match "ParentImage.*.*\w3wp.exe" -or $_.message -match "ParentImage.*.*\php-cgi.exe" -or $_.message -match "ParentImage.*.*\nginx.exe" -or $_.message -match "ParentImage.*.*\httpd.exe")) -and (($_.message -match "Image.*.*\cmd.exe") -and ($_.message -match "CommandLine.*.*perl --help.*" -or $_.message -match "CommandLine.*.*python --help.*" -or $_.message -match "CommandLine.*.*wget --help.*" -or $_.message -match "CommandLine.*.*perl -h.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}

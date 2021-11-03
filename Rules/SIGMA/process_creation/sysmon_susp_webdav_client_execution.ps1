# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\rundll32.exe" -and $_.message -match "CommandLine.*.*C:\windows\system32\davclnt.dll,DavSetCookie") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_webdav_client_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_webdav_client_execution";
            $detectedMessage = "A General detection for svchost.exe spawning rundll32.exe with command arguments like C:windowssystem32davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server).";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*C:\\windows\\system32\\davclnt.dll,DavSetCookie") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

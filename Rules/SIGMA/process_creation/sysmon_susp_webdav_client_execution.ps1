# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\rundll32.exe" -and $_.message -match "CommandLine.*.*C:\windows\system32\davclnt.dll,DavSetCookie.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_webdav_client_execution";
    $detectedMessage = "A General detection for svchost.exe spawning rundll32.exe with command arguments like C:windowssystem32davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server).";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\rundll32.exe" -and $_.message -match "CommandLine.*.*C:\windows\system32\davclnt.dll,DavSetCookie.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

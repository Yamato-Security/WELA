# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\curl.exe" -or $_.message -match "Product.*The curl executable") -and $_.message -match "CommandLine.*.* -O .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_curl_download";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_curl_download";
            $detectedMessage = "Detects a suspicious curl process start on Windows and outputs the requested document to a local file";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\curl.exe" -or $_.message -match "Product.*The curl executable") -and $_.message -match "CommandLine.*.* -O .*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

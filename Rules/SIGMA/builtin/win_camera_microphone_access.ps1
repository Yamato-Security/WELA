# Get-WinEvent -LogName Security | where {(($_.ID -eq "4657" -or $_.ID -eq "4656" -or $_.ID -eq "4663") -and ($_.message -match "ObjectName.*.*\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged" -or $_.message -match "ObjectName.*.*\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_camera_microphone_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_camera_microphone_access";
            $detectedMessage = "Potential adversaries accessing the microphone and webcam in an endpoint.";
            $result = $event |  where { (($_.ID -eq "4657" -or $_.ID -eq "4656" -or $_.ID -eq "4663") -and ($_.message -match "ObjectName.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged" -or $_.message -match "ObjectName.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

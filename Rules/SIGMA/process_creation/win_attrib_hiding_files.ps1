# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\attrib.exe" -and $_.message -match "CommandLine.*.* +h ") -and  -not ((($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\desktop.ini " -or ($_.message -match "ParentImage.*.*\cmd.exe" -and $_.message -match "CommandLine.*+R +H +S +A \.*.cui" -and $_.message -match "ParentCommandLine.*C:\WINDOWS\system32\.*.bat"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_attrib_hiding_files";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_attrib_hiding_files";
            $detectedMessage = "Detects usage of attrib.exe to hide files from users.";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\attrib.exe" -and $_.message -match "CommandLine.*.* +h ") -and -not ((($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\desktop.ini " -or ($_.message -match "ParentImage.*.*\\cmd.exe" -and $_.message -match "CommandLine.*+R +H +S +A \\.*.cui" -and $_.message -match "ParentCommandLine.*C:\\WINDOWS\\system32\\.*.bat"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

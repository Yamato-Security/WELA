# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and ($_.message -match "Image.*.*\whoami.exe" -or ($_.message -match "Image.*.*\wmic.exe" -and $_.message -match "CommandLine.*.*useraccount" -and $_.message -match "CommandLine.*.*get") -or ($_.message -match "Image.*.*\quser.exe" -or $_.message -match "Image.*.*\qwinsta.exe") -or ($_.message -match "Image.*.*\cmdkey.exe" -and $_.message -match "CommandLine.*.*/list") -or ($_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*dir " -and $_.message -match "CommandLine.*.*\Users\")) -and  -not (($_.message -match "CommandLine.*.* rmdir "))) -or (($_.ID -eq "1") -and (($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and $_.message -match "CommandLine.*.*user") -and  -not (($_.message -match "CommandLine.*.*/domain" -or $_.message -match "CommandLine.*.*/add" -or $_.message -match "CommandLine.*.*/delete" -or $_.message -match "CommandLine.*.*/active" -or $_.message -match "CommandLine.*.*/expires" -or $_.message -match "CommandLine.*.*/passwordreq" -or $_.message -match "CommandLine.*.*/scriptpath" -or $_.message -match "CommandLine.*.*/times" -or $_.message -match "CommandLine.*.*/workstations"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_local_system_owner_account_discovery";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_local_system_owner_account_discovery";
            $result = $event | where { (($_.ID -eq "1") -and ((($_.ID -eq "1") -and ($_.message -match "Image.*.*\\whoami.exe" -or ($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.*useraccount" -and $_.message -match "CommandLine.*.*get") -or ($_.message -match "Image.*.*\\quser.exe" -or $_.message -match "Image.*.*\\qwinsta.exe") -or ($_.message -match "Image.*.*\\cmdkey.exe" -and $_.message -match "CommandLine.*.*/list") -or ($_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*dir " -and $_.message -match "CommandLine.*.*\\Users\\")) -and -not (($_.message -match "CommandLine.*.* rmdir "))) -or (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*user") -and -not (($_.message -match "CommandLine.*.*/domain" -or $_.message -match "CommandLine.*.*/add" -or $_.message -match "CommandLine.*.*/delete" -or $_.message -match "CommandLine.*.*/active" -or $_.message -match "CommandLine.*.*/expires" -or $_.message -match "CommandLine.*.*/passwordreq" -or $_.message -match "CommandLine.*.*/scriptpath" -or $_.message -match "CommandLine.*.*/times" -or $_.message -match "CommandLine.*.*/workstations"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

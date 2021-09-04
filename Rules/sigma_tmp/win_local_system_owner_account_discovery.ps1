# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and ($_.message -match "Image.*.*\whoami.exe" -or ($_.message -match "Image.*.*\wmic.exe" -and $_.message -match "CommandLine.*.*useraccount.*" -and $_.message -match "CommandLine.*.*get.*") -or ($_.message -match "Image.*.*\quser.exe" -or $_.message -match "Image.*.*\qwinsta.exe") -or ($_.message -match "Image.*.*\cmdkey.exe" -and $_.message -match "CommandLine.*.*/list.*") -or ($_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*dir .*" -and $_.message -match "CommandLine.*.*\Users\.*")) -and  -not (($_.message -match "CommandLine.*.* rmdir .*"))) -or (($_.ID -eq "1") -and (($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and $_.message -match "CommandLine.*.*user.*") -and  -not (($_.message -match "CommandLine.*.*/domain.*" -or $_.message -match "CommandLine.*.*/add.*" -or $_.message -match "CommandLine.*.*/delete.*" -or $_.message -match "CommandLine.*.*/active.*" -or $_.message -match "CommandLine.*.*/expires.*" -or $_.message -match "CommandLine.*.*/passwordreq.*" -or $_.message -match "CommandLine.*.*/scriptpath.*" -or $_.message -match "CommandLine.*.*/times.*" -or $_.message -match "CommandLine.*.*/workstations.*"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_local_system_owner_account_discovery";
    $detectedMessage = "!detection!"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}

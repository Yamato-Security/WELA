# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.message -match "srservice" -or $_.message -match "ipvpn" -or $_.message -match "hkmsvc")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_apt_carbonpaper_turla";
    $detectedMessage = "This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "7045" -and ($_.message -match "srservice" -or $_.message -match "ipvpn" -or $_.message -match "hkmsvc")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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

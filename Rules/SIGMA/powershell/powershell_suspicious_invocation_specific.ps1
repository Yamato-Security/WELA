# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.message -match ".*-nop.*" -and $_.message -match ".* -w .*" -and $_.message -match ".*hidden.*" -and $_.message -match ".* -c .*" -and $_.message -match ".*[Convert]::FromBase64String.*") -or ($_.message -match ".* -w .*" -and $_.message -match ".*hidden.*" -and $_.message -match ".*-noni.*" -and $_.message -match ".*-nop.*" -and $_.message -match ".* -c .*" -and $_.message -match ".*iex.*" -and $_.message -match ".*New-Object.*") -or ($_.message -match ".* -w .*" -and $_.message -match ".*hidden.*" -and $_.message -match ".*-ep.*" -and $_.message -match ".*bypass.*" -and $_.message -match ".*-Enc.*") -or ($_.message -match ".*powershell.*" -and $_.message -match ".*reg.*" -and $_.message -match ".*add.*" -and $_.message -match ".*HKCU\software\microsoft\windows\currentversion\run.*") -or ($_.message -match ".*bypass.*" -and $_.message -match ".*-noprofile.*" -and $_.message -match ".*-windowstyle.*" -and $_.message -match ".*hidden.*" -and $_.message -match ".*new-object.*" -and $_.message -match ".*system.net.webclient.*" -and $_.message -match ".*.download.*") -or ($_.message -match ".*iex.*" -and $_.message -match ".*New-Object.*" -and $_.message -match ".*Net.WebClient.*" -and $_.message -match ".*.Download.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_suspicious_invocation_specific";
    $detectedMessage = "Detects suspicious PowerShell invocation command parameters"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.message -match ".*-nop.*" -and $_.message -match ".* -w .*" -and $_.message -match ".*hidden.*" -and $_.message -match ".* -c .*" -and $_.message -match ".*[Convert]::FromBase64String.*") -or ($_.message -match ".* -w .*" -and $_.message -match ".*hidden.*" -and $_.message -match ".*-noni.*" -and $_.message -match ".*-nop.*" -and $_.message -match ".* -c .*" -and $_.message -match ".*iex.*" -and $_.message -match ".*New-Object.*") -or ($_.message -match ".* -w .*" -and $_.message -match ".*hidden.*" -and $_.message -match ".*-ep.*" -and $_.message -match ".*bypass.*" -and $_.message -match ".*-Enc.*") -or ($_.message -match ".*powershell.*" -and $_.message -match ".*reg.*" -and $_.message -match ".*add.*" -and $_.message -match ".*HKCU\software\microsoft\windows\currentversion\run.*") -or ($_.message -match ".*bypass.*" -and $_.message -match ".*-noprofile.*" -and $_.message -match ".*-windowstyle.*" -and $_.message -match ".*hidden.*" -and $_.message -match ".*new-object.*" -and $_.message -match ".*system.net.webclient.*" -and $_.message -match ".*.download.*") -or ($_.message -match ".*iex.*" -and $_.message -match ".*New-Object.*" -and $_.message -match ".*Net.WebClient.*" -and $_.message -match ".*.Download.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
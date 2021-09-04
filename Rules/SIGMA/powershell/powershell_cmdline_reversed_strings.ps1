# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\powershell.exe" -and ($_.message -match "CommandLine.*.*hctac.*" -or $_.message -match "CommandLine.*.*kearb.*" -or $_.message -match "CommandLine.*.*dnammoc.*" -or $_.message -match "CommandLine.*.*ekovn.*" -or $_.message -match "CommandLine.*.*eliFd.*" -or $_.message -match "CommandLine.*.*rahc.*" -or $_.message -match "CommandLine.*.*etirw.*" -or $_.message -match "CommandLine.*.*golon.*" -or $_.message -match "CommandLine.*.*tninon.*" -or $_.message -match "CommandLine.*.*eddih.*" -or $_.message -match "CommandLine.*.*tpircS.*" -or $_.message -match "CommandLine.*.*ssecorp.*" -or $_.message -match "CommandLine.*.*llehsrewop.*" -or $_.message -match "CommandLine.*.*esnopser.*" -or $_.message -match "CommandLine.*.*daolnwod.*" -or $_.message -match "CommandLine.*.*tneilCbeW.*" -or $_.message -match "CommandLine.*.*tneilc.*" -or $_.message -match "CommandLine.*.*ptth.*" -or $_.message -match "CommandLine.*.*elifotevas.*" -or $_.message -match "CommandLine.*.*46esab.*" -or $_.message -match "CommandLine.*.*htaPpmeTteG.*" -or $_.message -match "CommandLine.*.*tcejbO.*" -or $_.message -match "CommandLine.*.*maerts.*" -or $_.message -match "CommandLine.*.*hcaerof.*" -or $_.message -match "CommandLine.*.*ekovni.*" -or $_.message -match "CommandLine.*.*retupmoc.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_cmdline_reversed_strings";
    $detectedMessage = "Detects the PowerShell command lines with reversed strings"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\powershell.exe" -and ($_.message -match "CommandLine.*.*hctac.*" -or $_.message -match "CommandLine.*.*kearb.*" -or $_.message -match "CommandLine.*.*dnammoc.*" -or $_.message -match "CommandLine.*.*ekovn.*" -or $_.message -match "CommandLine.*.*eliFd.*" -or $_.message -match "CommandLine.*.*rahc.*" -or $_.message -match "CommandLine.*.*etirw.*" -or $_.message -match "CommandLine.*.*golon.*" -or $_.message -match "CommandLine.*.*tninon.*" -or $_.message -match "CommandLine.*.*eddih.*" -or $_.message -match "CommandLine.*.*tpircS.*" -or $_.message -match "CommandLine.*.*ssecorp.*" -or $_.message -match "CommandLine.*.*llehsrewop.*" -or $_.message -match "CommandLine.*.*esnopser.*" -or $_.message -match "CommandLine.*.*daolnwod.*" -or $_.message -match "CommandLine.*.*tneilCbeW.*" -or $_.message -match "CommandLine.*.*tneilc.*" -or $_.message -match "CommandLine.*.*ptth.*" -or $_.message -match "CommandLine.*.*elifotevas.*" -or $_.message -match "CommandLine.*.*46esab.*" -or $_.message -match "CommandLine.*.*htaPpmeTteG.*" -or $_.message -match "CommandLine.*.*tcejbO.*" -or $_.message -match "CommandLine.*.*maerts.*" -or $_.message -match "CommandLine.*.*hcaerof.*" -or $_.message -match "CommandLine.*.*ekovni.*" -or $_.message -match "CommandLine.*.*retupmoc.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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

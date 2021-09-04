# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -NoP -sta -NonI -W Hidden -Enc .*" -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc .*" -or $_.message -match "CommandLine.*.* -NoP -NonI -W Hidden -enc .*" -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc.*" -or $_.message -match "CommandLine.*.* -enc  SQB.*" -or $_.message -match "CommandLine.*.* -nop -exec bypass -EncodedCommand .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_powershell_empire_launch";
    $detectedMessage = "Detects suspicious powershell command line parameters used in Empire"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -NoP -sta -NonI -W Hidden -Enc .*" -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc .*" -or $_.message -match "CommandLine.*.* -NoP -NonI -W Hidden -enc .*" -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc.*" -or $_.message -match "CommandLine.*.* -enc SQB.*" -or $_.message -match "CommandLine.*.* -nop -exec bypass -EncodedCommand .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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

# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -NoP -sta -NonI -W Hidden -Enc " -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc " -or $_.message -match "CommandLine.*.* -NoP -NonI -W Hidden -enc " -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc" -or $_.message -match "CommandLine.*.* -enc  SQB" -or $_.message -match "CommandLine.*.* -nop -exec bypass -EncodedCommand ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_powershell_empire_launch";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_powershell_empire_launch";
            $detectedMessage = "Detects suspicious powershell command line parameters used in Empire";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -NoP -sta -NonI -W Hidden -Enc " -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc " -or $_.message -match "CommandLine.*.* -NoP -NonI -W Hidden -enc " -or $_.message -match "CommandLine.*.* -noP -sta -w 1 -enc" -or $_.message -match "CommandLine.*.* -enc SQB" -or $_.message -match "CommandLine.*.* -nop -exec bypass -EncodedCommand ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\csi.exe" -or $_.message -match "Image.*.*\\rcsi.exe" -or $_.message -match "OriginalFileName.*csi.exe" -or $_.message -match "OriginalFileName.*rcsi.exe") -and $_.message -match "Company.*Microsoft Corporation") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_csi";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_csi";
            $detectedMessage = "Csi.exe is a signed binary from Micosoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft “"Roslyn”" Community Technology Preview was named 'rcsi.exe'";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\csi.exe" -or $_.message -match "Image.*.*\\rcsi.exe" -or $_.message -match "OriginalFileName.*csi.exe" -or $_.message -match "OriginalFileName.*rcsi.exe") -and $_.message -match "Company.*Microsoft Corporation") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

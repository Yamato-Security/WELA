# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\csi.exe" -or $_.message -match "Image.*.*\\rcsi.exe" -or $_.message -match "OriginalFileName.*csi.exe" -or $_.message -match "OriginalFileName.*rcsi.exe") -and $_.message -match "Company.*Microsoft Corporation") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_csi";
    $detectedMessage = "Csi.exe is a signed binary from Micosoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft “"Roslyn”" Community Technology Preview was named 'rcsi.exe'";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\csi.exe" -or $_.message -match "Image.*.*\\rcsi.exe" -or $_.message -match "OriginalFileName.*csi.exe" -or $_.message -match "OriginalFileName.*rcsi.exe") -and $_.message -match "Company.*Microsoft Corporation") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

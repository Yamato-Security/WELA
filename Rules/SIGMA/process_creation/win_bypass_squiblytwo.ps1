# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*http" -and ((($_.message -match "Image.*.*\wmic.exe") -and $_.message -match "CommandLine.*.*wmic" -and $_.message -match "CommandLine.*.*format") -or (($_.message -match "1B1A3F43BF37B5BFE60751F2EE2F326E" -or $_.message -match "37777A96245A3C74EB217308F3546F4C" -or $_.message -match "9D87C9D67CE724033C0B40CC4CA1B206") -and $_.message -match "CommandLine.*.*format:"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_bypass_squiblytwo";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_bypass_squiblytwo";
            $detectedMessage = "Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*http" -and ((($_.message -match "Image.*.*\\wmic.exe") -and $_.message -match "CommandLine.*.*wmic" -and $_.message -match "CommandLine.*.*format") -or (($_.message -match "1B1A3F43BF37B5BFE60751F2EE2F326E" -or $_.message -match "37777A96245A3C74EB217308F3546F4C" -or $_.message -match "9D87C9D67CE724033C0B40CC4CA1B206") -and $_.message -match "CommandLine.*.*format:"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}

# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Description.*?" -and ($_.message -match "FileVersion.*?" -or $_.message -match "Product.*?" -or $_.message -match "Company.*?") -and $_.message -match "Image.*.*\Downloads\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_file_characteristics";
    $detectedMessage = "Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Description.*?" -and ($_.message -match "FileVersion.*?" -or $_.message -match "Product.*?" -or $_.message -match "Company.*?") -and $_.message -match "Image.*.*\Downloads\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
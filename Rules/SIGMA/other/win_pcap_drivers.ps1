# Get-WinEvent -LogName Security | where {($_.ID -eq "4697" -and ($_.Service File Name -eq "*pcap*" -or $_.message -match "Service File Name.*.*npcap.*" -or $_.message -match "Service File Name.*.*npf.*" -or $_.message -match "Service File Name.*.*nm3.*" -or $_.message -match "Service File Name.*.*ndiscap.*" -or $_.message -match "Service File Name.*.*nmnt.*" -or $_.message -match "Service File Name.*.*windivert.*" -or $_.message -match "Service File Name.*.*USBPcap.*" -or $_.message -match "Service File Name.*.*pktmon.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_pcap_drivers";
    $detectedMessage = "Detects Windows Pcap driver installation based on a list of associated .sys files."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4697" -and ($_.Service File Name -eq "*pcap*" -or $_.message -match "Service File Name.*.*npcap.*" -or $_.message -match "Service File Name.*.*npf.*" -or $_.message -match "Service File Name.*.*nm3.*" -or $_.message -match "Service File Name.*.*ndiscap.*" -or $_.message -match "Service File Name.*.*nmnt.*" -or $_.message -match "Service File Name.*.*windivert.*" -or $_.message -match "Service File Name.*.*USBPcap.*" -or $_.message -match "Service File Name.*.*pktmon.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
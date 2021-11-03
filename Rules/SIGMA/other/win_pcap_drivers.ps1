# Get-WinEvent -LogName Security | where {($_.ID -eq "4697" -and ($_.Service File Name -eq "*pcap*" -or $_.message -match "Service File Name.*.*npcap" -or $_.message -match "Service File Name.*.*npf" -or $_.message -match "Service File Name.*.*nm3" -or $_.message -match "Service File Name.*.*ndiscap" -or $_.message -match "Service File Name.*.*nmnt" -or $_.message -match "Service File Name.*.*windivert" -or $_.message -match "Service File Name.*.*USBPcap" -or $_.message -match "Service File Name.*.*pktmon")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_pcap_drivers";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_pcap_drivers";
            $detectedMessage = "Detects Windows Pcap driver installation based on a list of associated .sys files.";
            $result = $event |  where { ($_.ID -eq "4697" -and ($_.message -Like "*pcap*" -or $_.message -match "Service File Name.*.*npcap" -or $_.message -match "Service File Name.*.*npf" -or $_.message -match "Service File Name.*.*nm3" -or $_.message -match "Service File Name.*.*ndiscap" -or $_.message -match "Service File Name.*.*nmnt" -or $_.message -match "Service File Name.*.*windivert" -or $_.message -match "Service File Name.*.*USBPcap" -or $_.message -match "Service File Name.*.*pktmon")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

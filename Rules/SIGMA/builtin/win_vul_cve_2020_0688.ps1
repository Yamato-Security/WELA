# Get-WinEvent -LogName Application | where {($_.ID -eq "4" -and $_.message -match "Source.*MSExchange Control Panel" -and $_.message -match "Level.*Error" -and ($_.message -match "&__VIEWSTATE=")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_vul_cve_2020_0688";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_vul_cve_2020_0688";
            $detectedMessage = "Detects the exploitation of Microsoft Exchange vulnerability as described in CVE-2020-0688 ";
            $result = $event | where { ($_.ID -eq "4" -and $_.message -match "Source.*MSExchange Control Panel" -and $_.message -match "Level.*Error" -and ($_.message -match "&__VIEWSTATE=")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Messagel;

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

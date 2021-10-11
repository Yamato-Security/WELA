# Get-WinEvent -LogName MSExchange Management | where {($_.message -match ".*Set-OabVirtualDirectory.*" -and $_.message -match ".*ExternalUrl.*" -and $_.message -match ".*Page_Load.*" -and $_.message -match ".*script.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_set_oabvirtualdirectory_externalurl";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_set_oabvirtualdirectory_externalurl";
            $detectedMessage = "Rule to detect an adversary setting OabVirtualDirectory External URL property to a script";
            $result = $event |  where { ($_.message -match ".*Set-OabVirtualDirectory.*" -and $_.message -match ".*ExternalUrl.*" -and $_.message -match ".*Page_Load.*" -and $_.message -match ".*script.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}

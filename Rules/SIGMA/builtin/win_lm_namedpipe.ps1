# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$") -and  -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and ($_.message -match "atsvc" -or $_.message -match "samr" -or $_.message -match "lsarpc" -or $_.message -match "winreg" -or $_.message -match "netlogon" -or $_.message -match "srvsvc" -or $_.message -match "protected_storage" -or $_.message -match "wkssvc" -or $_.message -match "browser" -or $_.message -match "netdfs" -or $_.message -match "svcctl" -or $_.message -match "spoolss" -or $_.message -match "ntsvcs" -or $_.message -match "LSM_API_service" -or $_.message -match "HydraLsPipe" -or $_.message -match "TermSrv_API_service" -or $_.message -match "MsFteWds"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_lm_namedpipe";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_lm_namedpipe";
            $detectedMessage = "This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes";
            $result = $event |  where { (($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$") -and -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$" -and ($_.message -match "atsvc" -or $_.message -match "samr" -or $_.message -match "lsarpc" -or $_.message -match "winreg" -or $_.message -match "netlogon" -or $_.message -match "srvsvc" -or $_.message -match "protected_storage" -or $_.message -match "wkssvc" -or $_.message -match "browser" -or $_.message -match "netdfs" -or $_.message -match "svcctl" -or $_.message -match "spoolss" -or $_.message -match "ntsvcs" -or $_.message -match "LSM_API_service" -or $_.message -match "HydraLsPipe" -or $_.message -match "TermSrv_API_service" -or $_.message -match "MsFteWds"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

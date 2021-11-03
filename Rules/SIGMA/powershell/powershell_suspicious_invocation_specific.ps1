# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.message -match "-nop" -and $_.message -match " -w " -and $_.message -match "hidden" -and $_.message -match " -c " -and $_.message -match "[Convert]::FromBase64String") -or ($_.message -match " -w " -and $_.message -match "hidden" -and $_.message -match "-noni" -and $_.message -match "-nop" -and $_.message -match " -c " -and $_.message -match "iex" -and $_.message -match "New-Object") -or ($_.message -match " -w " -and $_.message -match "hidden" -and $_.message -match "-ep" -and $_.message -match "bypass" -and $_.message -match "-Enc") -or ($_.message -match "powershell" -and $_.message -match "reg" -and $_.message -match "add" -and $_.message -match "HKCU\software\microsoft\windows\currentversion\run") -or ($_.message -match "bypass" -and $_.message -match "-noprofile" -and $_.message -match "-windowstyle" -and $_.message -match "hidden" -and $_.message -match "new-object" -and $_.message -match "system.net.webclient" -and $_.message -match ".download") -or ($_.message -match "iex" -and $_.message -match "New-Object" -and $_.message -match "Net.WebClient" -and $_.message -match ".Download"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_invocation_specific";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_suspicious_invocation_specific";
            $detectedMessage = "Detects suspicious PowerShell invocation command parameters";

            $result = $event | where {$_.message -match "hidden"} 
            if ($result -ne $null) {
                $tmp = $result | where {$_.message -match " -w "  } 
                if ($tmp -ne $null) {
                    $result += $tmp |  where { 
                        $_.message -match "-nop" -and $_.message -match " -c " -and $_.message -match "[Convert]::FromBase64String"}
                        $result += $tmp | where {$_.message -match "-noni" -and $_.message -match "-nop" -and $_.message -match " -c " -and $_.message -match "iex" -and $_.message -match "New-Object"}
                        $result += $tmp | where {
                            $_.message -match "-ep" -and $_.message -match "bypass" -and $_.message -match "-Enc"
                        }
                } else {
                    $result += $result | where {
                        $_.message -match "bypass" -and $_.message -match "-noprofile" -and $_.message -match "-windowstyle" -and $_.message -match "new-object" -and $_.message -match "system.net.webclient" -and $_.message -match ".download"
                    }
                }
            }
            $tmp = $event | where {$_.message -match "HKCU\\software\\microsoft\\windows\\currentversion\\run"} 
            if ($tmp -ne $null) {
                $result += $tmp | where {$_.message -match "powershell" -and $_.message -match "reg" -and $_.message -match "add"}

            }
            $tmp = $event | where {$_.message -match "Net\.WebClient"}
            if ($tmp -ne $null) {
                $result += $event | where {
                    $_.message -match "iex" -and $_.message -match "New-Object" -and $_.message -match "\.Download"
                }
            }
            Remove-Variable tmp

            $result = $result | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
           
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

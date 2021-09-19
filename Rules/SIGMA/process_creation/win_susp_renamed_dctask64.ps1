# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Imphash.*6834B1B94E49701D77CCB3C0895E1AFD" -and  -not ($_.message -match "Image.*.*\\dctask64.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_renamed_dctask64";
    $detectedMessage = "Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "Imphash.*6834B1B94E49701D77CCB3C0895E1AFD" -and -not ($_.message -match "Image.*.*\\dctask64.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}

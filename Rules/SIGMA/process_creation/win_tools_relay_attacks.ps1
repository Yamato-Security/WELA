# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*PetitPotam.*" -or $_.message -match "Image.*.*RottenPotato.*" -or $_.message -match "Image.*.*HotPotato.*" -or $_.message -match "Image.*.*JuicyPotato.*" -or $_.message -match "Image.*.*\just_dce_.*" -or $_.message -match "Image.*.*Juicy Potato.*" -or $_.message -match "Image.*.*\temp\rot.exe.*" -or $_.message -match "Image.*.*\Potato.exe.*" -or $_.message -match "Image.*.*\SpoolSample.exe.*" -or $_.message -match "Image.*.*\Responder.exe.*" -or $_.message -match "Image.*.*\smbrelayx.*" -or $_.message -match "Image.*.*\ntlmrelayx.*") -or ($_.message -match "CommandLine.*.*Invoke-Tater.*" -or $_.message -match "CommandLine.*.* smbrelay.*" -or $_.message -match "CommandLine.*.* ntlmrelay.*" -or $_.message -match "CommandLine.*.*cme smb .*" -or $_.message -match "CommandLine.*.* /ntlm:NTLMhash .*" -or $_.message -match "CommandLine.*.*Invoke-PetitPotam.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_tools_relay_attacks";
    $detectedMessage = "Detects different hacktools used for relay attacks on Windows for privilege escalation";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*PetitPotam.*" -or $_.message -match "Image.*.*RottenPotato.*" -or $_.message -match "Image.*.*HotPotato.*" -or $_.message -match "Image.*.*JuicyPotato.*" -or $_.message -match "Image.*.*\just_dce_.*" -or $_.message -match "Image.*.*Juicy Potato.*" -or $_.message -match "Image.*.*\temp\rot.exe.*" -or $_.message -match "Image.*.*\Potato.exe.*" -or $_.message -match "Image.*.*\SpoolSample.exe.*" -or $_.message -match "Image.*.*\Responder.exe.*" -or $_.message -match "Image.*.*\smbrelayx.*" -or $_.message -match "Image.*.*\ntlmrelayx.*") -or ($_.message -match "CommandLine.*.*Invoke-Tater.*" -or $_.message -match "CommandLine.*.* smbrelay.*" -or $_.message -match "CommandLine.*.* ntlmrelay.*" -or $_.message -match "CommandLine.*.*cme smb .*" -or $_.message -match "CommandLine.*.* /ntlm:NTLMhash .*" -or $_.message -match "CommandLine.*.*Invoke-PetitPotam.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}

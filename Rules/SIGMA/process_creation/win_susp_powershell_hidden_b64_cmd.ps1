# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.* hidden .*" -and ($_.message -match "CommandLine.*.*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA.*" -or $_.message -match "CommandLine.*.*aXRzYWRtaW4gL3RyYW5zZmVy.*" -or $_.message -match "CommandLine.*.*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA.*" -or $_.message -match "CommandLine.*.*JpdHNhZG1pbiAvdHJhbnNmZX.*" -or $_.message -match "CommandLine.*.*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg.*" -or $_.message -match "CommandLine.*.*Yml0c2FkbWluIC90cmFuc2Zlc.*" -or $_.message -match "CommandLine.*.*AGMAaAB1AG4AawBfAHMAaQB6AGUA.*" -or $_.message -match "CommandLine.*.*JABjAGgAdQBuAGsAXwBzAGkAegBlA.*" -or $_.message -match "CommandLine.*.*JGNodW5rX3Npem.*" -or $_.message -match "CommandLine.*.*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ.*" -or $_.message -match "CommandLine.*.*RjaHVua19zaXpl.*" -or $_.message -match "CommandLine.*.*Y2h1bmtfc2l6Z.*" -or $_.message -match "CommandLine.*.*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A.*" -or $_.message -match "CommandLine.*.*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg.*" -or $_.message -match "CommandLine.*.*lPLkNvbXByZXNzaW9u.*" -or $_.message -match "CommandLine.*.*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA.*" -or $_.message -match "CommandLine.*.*SU8uQ29tcHJlc3Npb2.*" -or $_.message -match "CommandLine.*.*Ty5Db21wcmVzc2lvb.*" -or $_.message -match "CommandLine.*.*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ.*" -or $_.message -match "CommandLine.*.*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA.*" -or $_.message -match "CommandLine.*.*lPLk1lbW9yeVN0cmVhb.*" -or $_.message -match "CommandLine.*.*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A.*" -or $_.message -match "CommandLine.*.*SU8uTWVtb3J5U3RyZWFt.*" -or $_.message -match "CommandLine.*.*Ty5NZW1vcnlTdHJlYW.*" -or $_.message -match "CommandLine.*.*4ARwBlAHQAQwBoAHUAbgBrA.*" -or $_.message -match "CommandLine.*.*5HZXRDaHVua.*" -or $_.message -match "CommandLine.*.*AEcAZQB0AEMAaAB1AG4Aaw.*" -or $_.message -match "CommandLine.*.*LgBHAGUAdABDAGgAdQBuAGsA.*" -or $_.message -match "CommandLine.*.*LkdldENodW5r.*" -or $_.message -match "CommandLine.*.*R2V0Q2h1bm.*" -or $_.message -match "CommandLine.*.*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A.*" -or $_.message -match "CommandLine.*.*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA.*" -or $_.message -match "CommandLine.*.*RIUkVBRF9JTkZPNj.*" -or $_.message -match "CommandLine.*.*SFJFQURfSU5GTzY0.*" -or $_.message -match "CommandLine.*.*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA.*" -or $_.message -match "CommandLine.*.*VEhSRUFEX0lORk82N.*" -or $_.message -match "CommandLine.*.*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA.*" -or $_.message -match "CommandLine.*.*cmVhdGVSZW1vdGVUaHJlYW.*" -or $_.message -match "CommandLine.*.*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA.*" -or $_.message -match "CommandLine.*.*NyZWF0ZVJlbW90ZVRocmVhZ.*" -or $_.message -match "CommandLine.*.*Q3JlYXRlUmVtb3RlVGhyZWFk.*" -or $_.message -match "CommandLine.*.*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA.*" -or $_.message -match "CommandLine.*.*0AZQBtAG0AbwB2AGUA.*" -or $_.message -match "CommandLine.*.*1lbW1vdm.*" -or $_.message -match "CommandLine.*.*AGUAbQBtAG8AdgBlA.*" -or $_.message -match "CommandLine.*.*bQBlAG0AbQBvAHYAZQ.*" -or $_.message -match "CommandLine.*.*bWVtbW92Z.*" -or $_.message -match "CommandLine.*.*ZW1tb3Zl.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_powershell_hidden_b64_cmd";
    $detectedMessage = "Detects base64 encoded strings used in hidden malicious PowerShell command lines"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.* hidden .*" -and ($_.message -match "CommandLine.*.*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA.*" -or $_.message -match "CommandLine.*.*aXRzYWRtaW4gL3RyYW5zZmVy.*" -or $_.message -match "CommandLine.*.*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA.*" -or $_.message -match "CommandLine.*.*JpdHNhZG1pbiAvdHJhbnNmZX.*" -or $_.message -match "CommandLine.*.*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg.*" -or $_.message -match "CommandLine.*.*Yml0c2FkbWluIC90cmFuc2Zlc.*" -or $_.message -match "CommandLine.*.*AGMAaAB1AG4AawBfAHMAaQB6AGUA.*" -or $_.message -match "CommandLine.*.*JABjAGgAdQBuAGsAXwBzAGkAegBlA.*" -or $_.message -match "CommandLine.*.*JGNodW5rX3Npem.*" -or $_.message -match "CommandLine.*.*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ.*" -or $_.message -match "CommandLine.*.*RjaHVua19zaXpl.*" -or $_.message -match "CommandLine.*.*Y2h1bmtfc2l6Z.*" -or $_.message -match "CommandLine.*.*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A.*" -or $_.message -match "CommandLine.*.*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg.*" -or $_.message -match "CommandLine.*.*lPLkNvbXByZXNzaW9u.*" -or $_.message -match "CommandLine.*.*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA.*" -or $_.message -match "CommandLine.*.*SU8uQ29tcHJlc3Npb2.*" -or $_.message -match "CommandLine.*.*Ty5Db21wcmVzc2lvb.*" -or $_.message -match "CommandLine.*.*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ.*" -or $_.message -match "CommandLine.*.*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA.*" -or $_.message -match "CommandLine.*.*lPLk1lbW9yeVN0cmVhb.*" -or $_.message -match "CommandLine.*.*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A.*" -or $_.message -match "CommandLine.*.*SU8uTWVtb3J5U3RyZWFt.*" -or $_.message -match "CommandLine.*.*Ty5NZW1vcnlTdHJlYW.*" -or $_.message -match "CommandLine.*.*4ARwBlAHQAQwBoAHUAbgBrA.*" -or $_.message -match "CommandLine.*.*5HZXRDaHVua.*" -or $_.message -match "CommandLine.*.*AEcAZQB0AEMAaAB1AG4Aaw.*" -or $_.message -match "CommandLine.*.*LgBHAGUAdABDAGgAdQBuAGsA.*" -or $_.message -match "CommandLine.*.*LkdldENodW5r.*" -or $_.message -match "CommandLine.*.*R2V0Q2h1bm.*" -or $_.message -match "CommandLine.*.*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A.*" -or $_.message -match "CommandLine.*.*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA.*" -or $_.message -match "CommandLine.*.*RIUkVBRF9JTkZPNj.*" -or $_.message -match "CommandLine.*.*SFJFQURfSU5GTzY0.*" -or $_.message -match "CommandLine.*.*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA.*" -or $_.message -match "CommandLine.*.*VEhSRUFEX0lORk82N.*" -or $_.message -match "CommandLine.*.*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA.*" -or $_.message -match "CommandLine.*.*cmVhdGVSZW1vdGVUaHJlYW.*" -or $_.message -match "CommandLine.*.*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA.*" -or $_.message -match "CommandLine.*.*NyZWF0ZVJlbW90ZVRocmVhZ.*" -or $_.message -match "CommandLine.*.*Q3JlYXRlUmVtb3RlVGhyZWFk.*" -or $_.message -match "CommandLine.*.*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA.*" -or $_.message -match "CommandLine.*.*0AZQBtAG0AbwB2AGUA.*" -or $_.message -match "CommandLine.*.*1lbW1vdm.*" -or $_.message -match "CommandLine.*.*AGUAbQBtAG8AdgBlA.*" -or $_.message -match "CommandLine.*.*bQBlAG0AbQBvAHYAZQ.*" -or $_.message -match "CommandLine.*.*bWVtbW92Z.*" -or $_.message -match "CommandLine.*.*ZW1tb3Zl.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
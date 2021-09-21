# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*.doc.exe" -or $_.message -match "Image.*.*.docx.exe" -or $_.message -match "Image.*.*.xls.exe" -or $_.message -match "Image.*.*.xlsx.exe" -or $_.message -match "Image.*.*.ppt.exe" -or $_.message -match "Image.*.*.pptx.exe" -or $_.message -match "Image.*.*.rtf.exe" -or $_.message -match "Image.*.*.pdf.exe" -or $_.message -match "Image.*.*.txt.exe" -or $_.message -match "Image.*.*      .exe" -or $_.message -match "Image.*.*______.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_double_extension";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_double_extension";
            $detectedMessage = "Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*.doc.exe" -or $_.message -match "Image.*.*.docx.exe" -or $_.message -match "Image.*.*.xls.exe" -or $_.message -match "Image.*.*.xlsx.exe" -or $_.message -match "Image.*.*.ppt.exe" -or $_.message -match "Image.*.*.pptx.exe" -or $_.message -match "Image.*.*.rtf.exe" -or $_.message -match "Image.*.*.pdf.exe" -or $_.message -match "Image.*.*.txt.exe" -or $_.message -match "Image.*.* .exe" -or $_.message -match "Image.*.*______.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}

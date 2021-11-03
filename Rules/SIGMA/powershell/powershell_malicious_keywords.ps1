# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "AdjustTokenPrivileges" -or $_.message -match "IMAGE_NT_OPTIONAL_HDR64_MAGIC" -or $_.message -match "Microsoft.Win32.UnsafeNativeMethods" -or $_.message -match "ReadProcessMemory.Invoke" -or $_.message -match "SE_PRIVILEGE_ENABLED" -or $_.message -match "LSA_UNICODE_STRING" -or $_.message -match "MiniDumpWriteDump" -or $_.message -match "PAGE_EXECUTE_READ" -or $_.message -match "SECURITY_DELEGATION" -or $_.message -match "TOKEN_ADJUST_PRIVILEGES" -or $_.message -match "TOKEN_ALL_ACCESS" -or $_.message -match "TOKEN_ASSIGN_PRIMARY" -or $_.message -match "TOKEN_DUPLICATE" -or $_.message -match "TOKEN_ELEVATION" -or $_.message -match "TOKEN_IMPERSONATE" -or $_.message -match "TOKEN_INFORMATION_CLASS" -or $_.message -match "TOKEN_PRIVILEGES" -or $_.message -match "TOKEN_QUERY" -or $_.message -match "Metasploit" -or $_.message -match "Mimikatz")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_malicious_keywords";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_malicious_keywords";
            $detectedMessage = "Detects keywords from well-known PowerShell exploitation frameworks";
            $result = $event |  where { (($_.message -match "AdjustTokenPrivileges" -or $_.message -match "IMAGE_NT_OPTIONAL_HDR64_MAGIC" -or $_.message -match "Microsoft.Win32.UnsafeNativeMethods" -or $_.message -match "ReadProcessMemory.Invoke" -or $_.message -match "SE_PRIVILEGE_ENABLED" -or $_.message -match "LSA_UNICODE_STRING" -or $_.message -match "MiniDumpWriteDump" -or $_.message -match "PAGE_EXECUTE_READ" -or $_.message -match "SECURITY_DELEGATION" -or $_.message -match "TOKEN_ADJUST_PRIVILEGES" -or $_.message -match "TOKEN_ALL_ACCESS" -or $_.message -match "TOKEN_ASSIGN_PRIMARY" -or $_.message -match "TOKEN_DUPLICATE" -or $_.message -match "TOKEN_ELEVATION" -or $_.message -match "TOKEN_IMPERSONATE" -or $_.message -match "TOKEN_INFORMATION_CLASS" -or $_.message -match "TOKEN_PRIVILEGES" -or $_.message -match "TOKEN_QUERY" -or $_.message -match "Metasploit" -or $_.message -match "Mimikatz")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

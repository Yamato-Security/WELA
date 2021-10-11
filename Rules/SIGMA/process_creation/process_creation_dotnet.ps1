# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*.dll" -or $_.message -match "CommandLine.*.*.csproj") -and ($_.message -match "Image.*.*\dotnet.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_dotnet";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_dotnet";
            $detectedMessage = "dotnet.exe will execute any DLL and execute unsigned code";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*.dll" -or $_.message -match "CommandLine.*.*.csproj") -and ($_.message -match "Image.*.*\\dotnet.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

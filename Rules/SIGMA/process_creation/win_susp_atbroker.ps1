# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*AtBroker.exe" -and $_.message -match "CommandLine.*.*start") -and  -not (($_.message -match "CommandLine.*.*animations" -or $_.message -match "CommandLine.*.*audiodescription" -or $_.message -match "CommandLine.*.*caretbrowsing" -or $_.message -match "CommandLine.*.*caretwidth" -or $_.message -match "CommandLine.*.*colorfiltering" -or $_.message -match "CommandLine.*.*cursorscheme" -or $_.message -match "CommandLine.*.*filterkeys" -or $_.message -match "CommandLine.*.*focusborderheight" -or $_.message -match "CommandLine.*.*focusborderwidth" -or $_.message -match "CommandLine.*.*highcontrast" -or $_.message -match "CommandLine.*.*keyboardcues" -or $_.message -match "CommandLine.*.*keyboardpref" -or $_.message -match "CommandLine.*.*magnifierpane" -or $_.message -match "CommandLine.*.*messageduration" -or $_.message -match "CommandLine.*.*minimumhitradius" -or $_.message -match "CommandLine.*.*mousekeys" -or $_.message -match "CommandLine.*.*Narrator" -or $_.message -match "CommandLine.*.*osk" -or $_.message -match "CommandLine.*.*overlappedcontent" -or $_.message -match "CommandLine.*.*showsounds" -or $_.message -match "CommandLine.*.*soundsentry" -or $_.message -match "CommandLine.*.*stickykeys" -or $_.message -match "CommandLine.*.*togglekeys" -or $_.message -match "CommandLine.*.*windowarranging" -or $_.message -match "CommandLine.*.*windowtracking" -or $_.message -match "CommandLine.*.*windowtrackingtimeout" -or $_.message -match "CommandLine.*.*windowtrackingzorder"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_atbroker";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_atbroker";
            $detectedMessage = "Atbroker executing non-deafualt Assistive Technology applications";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*AtBroker.exe" -and $_.message -match "CommandLine.*.*start") -and -not (($_.message -match "CommandLine.*.*animations" -or $_.message -match "CommandLine.*.*audiodescription" -or $_.message -match "CommandLine.*.*caretbrowsing" -or $_.message -match "CommandLine.*.*caretwidth" -or $_.message -match "CommandLine.*.*colorfiltering" -or $_.message -match "CommandLine.*.*cursorscheme" -or $_.message -match "CommandLine.*.*filterkeys" -or $_.message -match "CommandLine.*.*focusborderheight" -or $_.message -match "CommandLine.*.*focusborderwidth" -or $_.message -match "CommandLine.*.*highcontrast" -or $_.message -match "CommandLine.*.*keyboardcues" -or $_.message -match "CommandLine.*.*keyboardpref" -or $_.message -match "CommandLine.*.*magnifierpane" -or $_.message -match "CommandLine.*.*messageduration" -or $_.message -match "CommandLine.*.*minimumhitradius" -or $_.message -match "CommandLine.*.*mousekeys" -or $_.message -match "CommandLine.*.*Narrator" -or $_.message -match "CommandLine.*.*osk" -or $_.message -match "CommandLine.*.*overlappedcontent" -or $_.message -match "CommandLine.*.*showsounds" -or $_.message -match "CommandLine.*.*soundsentry" -or $_.message -match "CommandLine.*.*stickykeys" -or $_.message -match "CommandLine.*.*togglekeys" -or $_.message -match "CommandLine.*.*windowarranging" -or $_.message -match "CommandLine.*.*windowtracking" -or $_.message -match "CommandLine.*.*windowtrackingtimeout" -or $_.message -match "CommandLine.*.*windowtrackingzorder"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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

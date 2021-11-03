
function Add-Rule {
    $ruleName = "4625_4648-PassSprayAttack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4625_4648-PassSprayAttack";
            $detectedMessage = "Distributed Account Explicit Credential Use (Password Spray Attack) in timeframe on WELA";        
            $target = $event | where { $_.LogName -eq "Security" -and ($_.id -eq 4648 -or $_.id -eq 4625) }

            $PasswordGuessDetection = @{ FirstDetect = $null ; Count = 0 }
            $PasswordGuessTimeframeMinutes = 1
            $PasswordGuessCount = 3
            $DBCPassSprayTrack = @{};
            $DBCpasssprayuniqusermax = 6
            $DBCpasssprayloginmax = 6
            $DBCpasssprayuniquser = 0

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml()
                $username = $eventXML.Event.EventData.Data[1]."#text"
                $hostname = $eventXML.Event.EventData.Data[2]."#text"
                $targetusername = $eventXML.Event.EventData.Data[5]."#text"
                $sourceip = ""
                if ($record.id -eq 4648) {
                    $sourceip = $eventXML.Event.EventData.Data[12]."#text"
                    # DeepBlueCLI passspary logic
                    $DBCPassSprayTrack[$targetusername] += 1;
                    if ($DBCPassSprayTrack[$targetusername] -gt $DBCpasssprayloginmax) {
                        foreach ($key in $DBCpassspraytrack.keys) {
                            if ($DBCpassspraytrack[$key] -gt $DBCpasssprayloginmax) { 
                                $DBCpasssprayuniquser += 1
                            }
                        }
                        if ($DBCpasssprayuniquser -gt $DBCpasssprayuniqusermax) {
                            $usernames = ""
                            foreach ($key in $DBCpassspraytrack.keys) {
                                $usernames += $key
                                $usernames += " "
                            }
                            $result = Create-Obj $record $LogFile
                            $result.EventID = 4648
                            $result.Message = "Distributed Account Explicit Credential Use (Password Spray Attack)"
                            $result.Results = "The use of multiple user account access attempts with explicit credentials is "
                            $result.Results += "an indicator of a password spray attack.`n"
                            $result.Results += "Target Usernames: $usernames`n"
                            $result.Results += "Accessing Username: $username`n"
                            $result.Results += "Accessing Host Name: $hostname`n"
                            Write-Output ""
                            Write-Output "Detected!RuleName:$ruleName(DeepBlueCLI Rule)"
                            Write-Output $result
                            $DBCpassspraytrack = @{} # Reset
                        }
                    }
                }
                else {
                    $sourceip = $eventXML.Event.EventData.Data[19]."#text"
                }
                $EventTimestampString = $record.TimeCreated.ToString($DateFormat)
                $EventTimestampDateTime = [datetime]::ParseExact($EventTimestampString, $DateFormat, $null)
                if (!$PasswordGuessDetection.FirstDetect) {
                    $PasswordGuessDetection.FirstDetect = [datetime]::ParseExact($EventTimestampString, $DateFormat, $null);
                    $PasswordGuessDetection.Count++;
                }
                else {
                    $TimeBetweenEvents = ( $EventTimestampDateTime - $PasswordGuessDetection.FirstDetect ).TotalMinutes
                    if ($TimeBetweenEvents -gt $PasswordGuessTimeframeMinutes) {
                        $PasswordGuessDetection.FirstDetect = $null
                        $PasswordGuessDetection.Count = 0
                    }
                    else {
                        $PasswordGuessDetection.Count++;
                        if ( $PasswordGuessDetection.Count -ge $PasswordGuessCount -and $TimeBetweenEvents -gt 0 ) {
                            $result = Create-Obj $record $LogFile
                            $result.Message = $detectedMessage
                            $result.Results = "Target User: $targetusername`nIP Address: $sourceip (Threshold: $PasswordGuessCount times in $PasswordGuessTimeframeMinutes minutes.)"
                            Write-Output ""
                            Write-Output "Detected!RuleName:$ruleName(WELA Rule)"
                            Write-Output $result
                            $PasswordGuessDetection.FirstDetect = $PasswordGuessDetection.FirstDetect.Addminutes($PasswordGuessTimeframeMinutes)
                            $PasswordGuessDetection.Count = 0
                        }
                    }
                }
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
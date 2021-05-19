<#
.SYNOPSIS
Fast forensics timeline generator for the Windows security event log.

.DESCRIPTION
The YEA security event timeline generator is a fast Forensics PowerShell module to create easy to analyze and as noise-free as possible event timeline for the Windows security log.

.Example
Process the local Windows security event log (Need to run with Administrator privileges):
.\yea-security-timeline.ps1

.Example
Process an offline Windows security event log:

.\DeepBlue.ps1 -path E:\logs\Security.evtx

.LINK
https://github.com/yamatosecurity
#>

# Yamato Event Analyzer (YEA) Security event timeline generator
# Zach Mathis, Yamatosecurity founder
# Twitter: @yamatosecurity
# https://yamatosecurity.connpass.com/
# 
# Inspired by Eric Conrad's DeepBlueCLI (https://github.com/sans-blue-team/DeepBlueCLI)
# Much help from the Windows Event Log Analysis Cheatsheets by Steve Anson (https://www.forwarddefense.com/en/article/references-pdf)

param (
    [bool]$Japanese = $false,
    [bool]$USDateFormat = $false,
    [bool]$EuropeDateFormat = $false,
    [string]$SaveOutput = "",
    [string]$StartTimeline = "",
    [string]$EndTimeline = "",
    [bool]$IsDC = $false,
    [bool]$ShowLogonID = $false,
    [bool]$LiveAnalysis = $false,
    [string]$LogFile = "",
    [bool]$ShowContributors = $false,
    [bool]$EventIDStatistics = $false,
    [bool]$LogonTimeline = $false,
    [bool]$AccountInformation = $false,
    [bool]$OutputGUI = $false,
    [bool]$OutputCSV = $false,
    [bool]$UTC = $false,
    [bool]$DisplayTimezone = $true
)

$ProgramStartTime = Get-Date


#Functions:
function Show-Contributors {
    Write-Host 
    Write-Host "Contributors:"
    Write-Host "DustInDark - Localization"
    Write-Host
    Write-Host "Please contribute to this project for fame and glory!"
    Write-Host
}


function Logon-Number-To-String($msgLogonType) {
    switch ( $msgLogonType ) {
        "0" { $msgLogonTypeReadable = "System" }
        "2" { $msgLogonTypeReadable = "Interactive" }
        "3" { $msgLogonTypeReadable = "Network" }
        "4" { $msgLogonTypeReadable = "Batch" }
        "5" { $msgLogonTypeReadable = "Service" }
        "7" { $msgLogonTypeReadable = "Unlock" }
        "8" { $msgLogonTypeReadable = "NetworkCleartext" }
        "9" { $msgLogonTypeReadable = "NewCredentials" }
        "10" { $msgLogonTypeReadable = "RemoteInteractive" }
        "11" { $msgLogonTypeReadable = "CachedInteractive" }
        "12" { $msgLogonTypeReadable = "CachedRemoteInteractive" }
        "13" { $msgLogonTypeReadable = "CachedUnlock" }
        default { $msgLogonTypeReadable = "Unknown" }
    }

    return $msgLogonTypeReadable
}

function Is-Logon-Dangerous ( $msgLogonType ) {
    switch ( $msgLogonType ) {
        "0" { $msgIsLogonDangerous = "" }
        "2" { $msgIsLogonDangerous = "(Dangerous! Credential information is stored in memory and maybe be stolen for account hijacking.)" }
        "3" { $msgIsLogonDangerous = "" }
        "4" { $msgIsLogonDangerous = "" }
        "5" { $msgIsLogonDangerous = "" }
        "7" { $msgIsLogonDangerous = "" }
        "8" { $msgIsLogonDangerous = "(Dangerous! Unhashed passwords were used for authentication.)" }
        "9" { $msgIsLogonDangerous = "(Dangerous! Credential information is stored in memory and maybe be stolen for account hijacking.)" }
        "10" { $msgIsLogonDangerous = "(Dangerous! Credential information is stored in memory and maybe be stolen for account hijacking.)" }
        "11" { $msgIsLogonDangerous = "" }
        "12" { $msgIsLogonDangerous = "" }
        "13" { $msgIsLogonDangerous = "" }
        default { $msgIsLogonDangerous = "" }
    }

    return $msgIsLogonDangerous
}

Function Format-FileSize {
    Param ([int]$size)
    If ($size -gt 1TB) { [string]::Format("{0:0.00} TB", $size / 1TB) }
    ElseIf ($size -gt 1GB) { [string]::Format("{0:0.00} GB", $size / 1GB) }
    ElseIf ($size -gt 1MB) { [string]::Format("{0:0.00} MB", $size / 1MB) }
    ElseIf ($size -gt 1KB) { [string]::Format("{0:0.00} kB", $size / 1KB) }
    ElseIf ($size -gt 0) { [string]::Format("{0:0.00} B", $size) }
    Else { "" }
}

function Check-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}


#Global variables

$YEAVersion = "0.1"

$EventIDsToAnalyze = "4624,4625,4672,4634,4647,4720,4732,1102,4648,4776"
# Logs to filter for:
# 4624 - LOGON
# 4625 - FAILED LOGON
# 4672 - ADMIN LOGON (Special privileges assigned to a new logon)
# 4634 - LOGOFF
# 4647 - LOGOFF
# 4720 - User account created
# 4732 - User added to group
# 1102 - LOG CLEARED
# 4648 - EXPLICIT LOGON
# 4776 - NTLM LOGON TO LOCAL ACCOUNT (TODO)

# Additional logs to filter for if a DC
# 4768 - TGT ISSUED
# 4769 - SERVICE TICKET ISSUED
# 4776 - NTLM auth. non-standard tool used?

$TotalLogsNoFilters = 0
$BadWorkstations = @("kali", "SLINGSHOT") #Highlight with the red alert background when the workstation comes from a pentesting distro.

#Set the output colors
#16 possible colors are Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White
#Only 6 readable colors with default black background: Green, Red, Cyan, Magenta, Gray, Yellow

$EventID_4624_Color = "Green"       #Successful logon
$EventID_4648_Color = "Yellow"       #Explicit logon to another user
$EventID_4672_Color = "Yellow"       #Admin logon
$EventID_4625_Color = "Red"         #Failed logon 
$EventID_4634_Color = "Gray"        #Logoff
$EventID_4647_Color = "Gray"        #Logoff
$EventID_4720_Color = "Yellow"     #Account Created
$EventID_4732_Color = "Yellow"     #User added to a group
$EventID_1102_Color = "Red"     #Log cleared
$ParameterColor = "Cyan"

$LogNoise = 0
$TotalPiecesOfData = 0
$AlertedEvents = 0
$SkippedLogs = 0
$TotalLogs = 0

$HostLanguage = Get-WinSystemLocale | Select-Object Name # en-US, ja-JP, etc..

if ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {
    Import-Module './Config/Language/ja.ps1' -Force;
}
else {
    Import-Module './Config/Language/en.ps1' -Force;
}

#Set the date format
$DateFormat = "yyyy-MM-dd HH:mm:ss.ff"

if ( $USDateFormat -eq $true ) {
    $DateFormat = "MM/dd/yyyy HH:mm:ss.ff"
} 

if ( $EuropeDateFormat -eq $true ) {
    $DateFormat = "dd.MM.yyyy HH:mm:ss.ff"
} 

function EventInfo ($eventIDNumber) {
    
    [hashtable]$return = @{}

    switch ( $eventIDNumber ) {
        "1100" { $return = $1100 }
        "1101" { $return = $1101 }
        "1102" { $return = $1102 }
        "1107" { $return = $1107 }
        "4608" { $return = $4608 }
        "4610" { $return = $4610 }
        "4611" { $return = $4611 }
        "4614" { $return = $4614 }
        "4616" { $return = $4616 }
        "4622" { $return = $4622 }
        "4624" { $return = $4624 }
        "4625" { $return = $4625 }
        "4634" { $return = $4634 }
        "4647" { $return = $4647 }
        "4648" { $return = $4648 }
        "4672" { $return = $4672 }
        "4688" { $return = $4688 }
        "4696" { $return = $4696 }
        "4692" { $return = $4692 }
        "4697" { $return = $4697 }
        "4717" { $return = $4717 }
        "4719" { $return = $4719 }
        "4720" { $return = $4720 }
        "4722" { $return = $4722 }
        "4724" { $return = $4724 }
        "4725" { $return = $4725 }
        "4726" { $return = $4726 }
        "4728" { $return = $4728 }
        "4729" { $return = $4729 }
        "4732" { $return = $4732 }
        "4733" { $return = $4733 }
        "4735" { $return = $4735 }
        "4727" { $return = $4727 }
        "4738" { $return = $4738 }
        "4739" { $return = $4739 }
        "4776" { $return = $4776 }
        "4778" { $return = $4778 }
        "4779" { $return = $4779 }
        "4797" { $return = $4797 }
        "4798" { $return = $4798 }
        "4799" { $return = $4799 }
        "4781" { $return = $4781 }
        "4800" { $return = $4800 }
        "4801" { $return = $4801 }
        "4826" { $return = $4826 }
        "4902" { $return = $4902 }
        "4904" { $return = $4904 }
        "4905" { $return = $4905 }
        "4907" { $return = $4907 }
        "4944" { $return = $4944 }
        "4945" { $return = $4945 }
        "4946" { $return = $4946 }
        "4947" { $return = $4947 }
        "4948" { $return = $4948 }
        "4954" { $return = $4954 }
        "4956" { $return = $4956 }
        "5024" { $return = $5024 }
        "5033" { $return = $5033 }
        "5038" { $return = $5038 }
        "5058" { $return = $5058 }
        "5059" { $return = $5059 }
        "5061" { $return = $5061 }
        "5140" { $return = $5140 }
        "5142" { $return = $5142 }
        "5144" { $return = $5144 }
        "5379" { $return = $5379 }
        "5381" { $return = $5381 }
        "5382" { $return = $5382 }
        "5478" { $return = $5478 }
        "5889" { $return = $5889 }
        "5890" { $return = $5890 }
        default { $return = $unregistered }
    }

    return $return

}


function Create-EventIDStatistics {

    #TODO:
    # - Implement save-output
    # - Add comments to event IDs
    # - Explicitly output results in a table
    # - Translate everything

    Write-Host
    Write-Host "Creating Event ID Statistics"
    Write-Host "Please be patient."
    Write-Host
    
    $WineventFilter = @{}
    
    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }

    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }

    #Live Analysis
    if ( $LogFile -eq "" ) {
        
        Perform-LiveAnalysisChecks

        $WineventFilter.Add("LogName", "Security")
        $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest
        $eventlist = @{}
        $TotalNumberOfLogs = 0

        foreach ( $event in $logs ) {

            $id = $event.id.toString()

            if ( $eventlist[$id] -eq $null ) {

                $eventlist[$id] = 1

            } 
            
            else {

                $eventlist[$id] += 1
            }

            $TotalNumberOfLogs++
        }

        #Print results
        $filesize = Format-FileSize( (get-item "C:\Windows\System32\winevt\Logs\Security.evtx").length )
        $FirstEventTimestamp = $logs[0].TimeCreated.ToString($DateFormat) 
        $LastEventTimestamp = $logs[-1].TimeCreated.ToString($DateFormat)  
    
        Write-Host "Total Event Logs: $TotalNumberOfLogs"
        Write-Host "File Size: $filesize"
        Write-Host "First event: $FirstEventTimestamp"
        Write-Host "Last event: $LastEventTimestamp"
    
        $sorted = $eventlist.GetEnumerator() | sort Value -Descending    #sorted gets turn into an array    
        [System.Collections.ArrayList]$ArrayWithHeader = @()
        
        for ( $i = 0 ; $i -le ( $sorted.count - 1 ) ; $i++) {
                 
            $Name = $sorted[$i].Name
            $Value = $sorted[$i].Value
            $EventInfo = EventInfo($Name)
            $PercentOfLogs = [math]::Round( ( $Value / $TotalNumberOfLogs * 100 ), 1 )
            $CountPlusPercent = "$value ($PercentOfLogs%)" 
            $val = [pscustomobject]@{'Count' = $CountPlusPercent ; 'ID' = $Name ; 'Event' = $EventInfo.EventTitle ; 'Timeline Detection' = $EventInfo.TimelineDetect } #; 'Comment' = $EventInfo.Comment
            $ArrayWithHeader.Add($val) > $null

        }

        $ProgramEndTime = Get-Date
        $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
        $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
        $RuntimeHours = $TempTimeSpan.Hours.ToString()
        $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
        $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

        Write-Host
        Write-Host "Processing time: $RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"

        $ArrayWithHeader

    }

    #Offline Log Analysis
    Else {

        $WineventFilter.Add( "Path", $LogFile ) 
        $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest
        $eventlist = @{}
        $TotalNumberOfLogs = 0

        foreach ( $event in $logs ) {

            $id = $event.id.toString()

            if ( $eventlist[$id] -eq $null ) {

                $eventlist[$id] = 1

            } 
            
            else {

                $eventlist[$id] += 1

            }

            $TotalNumberOfLogs++

        }

        #Print results        
        $filesize = Format-FileSize( (get-item $LogFile).length )
        $FirstEventTimestamp = $logs[0].TimeCreated.ToString($DateFormat) 
        $LastEventTimestamp = $logs[-1].TimeCreated.ToString($DateFormat)  

        Write-Host "Total Event Logs: $TotalNumberOfLogs"
        Write-Host "File Size: $filesize"
        Write-Host "First event: $FirstEventTimestamp"
        Write-Host "Last event: $LastEventTimestamp"
    
        $sorted = $eventlist.GetEnumerator() | sort Value -Descending    #sorted gets turn into an array    
        [System.Collections.ArrayList]$ArrayWithHeader = @()
        
        for ( $i = 0 ; $i -le ( $sorted.count - 1 ) ; $i++) {
                 
            $Name = $sorted[$i].Name
            $Value = $sorted[$i].Value
            $EventInfo = EventInfo($Name)
            $PercentOfLogs = [math]::Round( ( $Value / $TotalNumberOfLogs * 100 ), 1 )
            $CountPlusPercent = "$value ($PercentOfLogs%)" 
            $val = [pscustomobject]@{'Count' = $CountPlusPercent ; 'ID' = $Name ; 'Event' = $EventInfo.EventTitle ; 'Timeline Detection' = $EventInfo.TimelineDetect } #; 'Comment' = $EventInfo.Comment
            $ArrayWithHeader.Add($val) > $null

        }

        $ProgramEndTime = Get-Date
        $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
        $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
        $RuntimeHours = $TempTimeSpan.Hours.ToString()
        $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
        $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

        Write-Host
        Write-Host "Processing time: $RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"

        $ArrayWithHeader

    }


}

function Create-LogonTimeline {

    #TODO:
    #Output only odd hour times
    #Color to table

    # Notes: 
    #   Logoff events without corresponding logon events first won't be printed
    #   The log service shutdown time is used for the shutdown time so might be wrong if the log service was turned off while the system was running. (anti-forensics, etc..)

    Write-Host
    Write-Host $Create_LogonTimeline_Welcome_Message #Creating a logon overview excluding service account logons, noisy local system logons and machine account logons.`nPlease be patient.
    Write-Host
    
    $WineventFilter = @{}
    $EventIDsToAnalyze = 4624, 4634, 4647, 1100
    $WineventFilter.Add("ID", $EventIDsToAnalyze)
    $TotalLogonEvents = 0
    $TotalFilteredLogons = 0
    $Type0Logons = 0
    $Type2Logons = 0
    $Type3Logons = 0
    $Type4Logons = 0
    $Type5Logons = 0
    $Type7Logons = 0
    $Type8Logons = 0
    $Type9Logons = 0
    $Type10Logons = 0
    $Type11Logons = 0
    $Type12Logons = 0
    $Type13Logons = 0
    $OtherTypeLogon = 0

    $output = @()
    $LogServiceShutdownTimeArray = @()
    
    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }

    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }

    #Live Analysis
    if ( $LogFile -eq "" ) {

        Perform-LiveAnalysisChecks
        $WineventFilter.Add( "LogName", "Security" )
        $filesizeMB = (Get-Item "C:\Windows\System32\winevt\Logs\Security.evtx").Length / 1MB
        $filesize = Format-FileSize( (get-item "C:\Windows\System32\winevt\Logs\Security.evtx").length )

    }
    else {

        $WineventFilter.Add( "Path", $LogFile )
        $filesize = Format-FileSize( (get-item $LogFile).length )
        $filesizeMB = (Get-Item $LogFile).length / 1MB 
    }

    $filesizeMB = $filesizeMB * 0.1
    $ApproxTimeInSeconds = $filesizeMB * 60
    $TempTimeSpan = New-TimeSpan -Seconds $ApproxTimeInSeconds
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host ( $Create_LogonTimeline_Filesize -f $filesize )          # "File Size: {0}"
    Write-Host ( $Create_LogonTimeline_Estimated_Processing_Time -f $RuntimeHours, $RuntimeMinutes, $RuntimeSeconds )   # "Estimated processing time: {0} hours {1} minutes {2} seconds"

    $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest
    $eventlist = @{}
    $TotalNumberOfLogs = 0

    [System.Collections.ArrayList]$LogoffEventArray = @()

    #Create an array of timestamps and logon IDs for logoff events
    foreach ( $event in $logs ) {
            
        # 4634 Logoff
        if ($event.Id -eq "4634") { 
            
            $TotalLogonEvents++
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                        
                    "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                }
            }
            
            if ( $UTC -eq $true ) {
                $LogoffTimestampString = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ff")
            }
            else {
                $LogoffTimestampString = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.ff") 
            }

            $LogoffTimestampDateTime = [datetime]::ParseExact($LogoffTimestampString, 'yyyy-MM-dd HH:mm:ss.ff', $null) 
            $LogoffEvent = @( $msgTargetLogonID , $LogoffTimestampDateTime )
            $LogoffEventArray.Add( $LogoffEvent ) > $null
        }

        # 4647 Logoff
        if ($event.Id -eq "4647") { 

            $TotalLogonEvents++
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                        
                    "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                }
            }
            
            if ( $UTC -eq $true ) {
                $LogoffTimestampString = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ff")
            }
            else {
                $LogoffTimestampString = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.ff") 
            }

            $LogoffTimestampDateTime = [datetime]::ParseExact($LogoffTimestampString, 'yyyy-MM-dd HH:mm:ss.ff', $null) 
            $LogoffEvent = @( $msgTargetLogonID , $LogoffTimestampDateTime )
            $LogoffEventArray.Add( $LogoffEvent ) > $null

        }
            
        # 1100 Event log service stopped
        if ($event.Id -eq "1100") { 

            $TotalLogonEvents++
            $eventXML = [xml]$event.ToXml()
            <#
            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                        
                    "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                }
            }
            #>

            if ( $UTC -eq $true ) {
                $LogServiceShutdownTimeString = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ff")
            }
            else {
                $LogServiceShutdownTimeString = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.ff") 
            }

            $LogServiceShutdownTimeDateTime = [datetime]::ParseExact($LogServiceShutdownTimeString, 'yyyy-MM-dd HH:mm:ss.ff', $null) 
            $LogServiceShutdownTimeArray += $LogServiceShutdownTimeDateTime 

        }
                        
    }
                       

    foreach ( $event in $logs ) {
        
        #Successful logon

        if ($event.Id -eq "4624") { 

            $TotalLogonEvents++
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                        
                    "LogonType" { $msgLogonType = $data.'#text' }
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "WorkstationName" { $msgWorkstationName = $data.'#text' }
                    "IpAddress" { $msgIpAddress = $data.'#text' }
                    "IpPort" { $msgIpPort = $data.'#text' }
                    "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                    "SubjectUserSid" { $msgSubjectUserSid = $data.'#text' } 

                }

            }

            $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings
            $LogoffTimestampString = "" 
            $LogServiceShutdownTimeString = ""

            if ( $UTC -eq $true ) {
                $LogonTimestampString = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ff") 
            } else {
                $LogonTimestampString = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.ff") 
            }

            $LogonTimestampDateTime = [datetime]::ParseExact($LogonTimestampString, 'yyyy-MM-dd HH:mm:ss.ff', $null)

            if ( $msgLogonType -eq "0" ) { #if System startup/runtime

                foreach ( $LogServiceShutdownTime in $LogServiceShutdownTimeArray ) {

                    if ( $LogServiceShutdownTime -gt $LogonTimestampDateTime -and $LogoffTimestampString -eq "" ) {
                       
                        $LogoffTimestampString = $LogServiceShutdownTime.ToString("yyyy-MM-dd HH:mm:ss.ff") 
                        $ElapsedTime = $LogServiceShutdownTime - $LogonTimestampDateTime

                    }     
                    
                }

            } else #regular logon events
            {
 
                foreach ( $EventIndex in $LogoffEventArray ) {
                
                    # $EventIndex[0] -> Logoff Logon ID
                    # $EventIndex[1] -> Logoff time
                    # If the logon ID match and the logoff date is greater than the logon date and $LogoffTimestampString is blank (to prevent skipping to an older duplicate logon id (rare case?))
                    if ( $EventIndex[0] -eq $msgTargetLogonID -and $EventIndex[1] -ge $LogonTimestampDateTime -and $LogoffTimestampString -eq "" ) {
                       
                        $LogoffTimestampString = $EventIndex[1].ToString("yyyy-MM-dd HH:mm:ss.ff") 
                        $ElapsedTime = $EventIndex[1] - $LogonTimestampDateTime

                    }     
                    
                }

            }

            $TotalRuntime = [math]::Round(($ElapsedTime).TotalSeconds)
            $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
            $RuntimeDays = $TempTimeSpan.Days.ToString()
            $RuntimeHours = $TempTimeSpan.Hours.ToString()
            $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
            $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()
            #$RuntimeMilliSeconds = $TempTimeSpan.Milliseconds.ToString()

            $ElapsedTimeOutput = ""
            if ( $LogoffTimestampString -eq "") {

                $LogoffTimestampString = $Create_LogonTimeline_NoLogoffEvent # "No logoff event"

            }

            else {

                $ElapsedTimeOutput = ($Create_LogonTimeline_ElapsedTimeOutput -f $RuntimeDays , $RuntimeHours , $RuntimeMinutes , $RuntimeSeconds )
            }
    
            switch ( $msgLogonType ) {
                "0" { $Type0Logons++ } #System
                "2" { $Type2Logons++ } #Interactive
                "3" { $Type3Logons++ } #Network
                "4" { $Type4Logons++ } #Batch
                "5" { $Type5Logons++ } #Service
                "7" { $Type7Logons++ } #NetworkCleartext
                "8" { $Type8Logons++ } #NetworkCleartext
                "9" { $Type9Logons++ } #Explicit Logon
                "10" { $Type10Logons++ } #RDP
                "11" { $Type11Logons++ } #Cached Credentials
                "12" { $Type12Logons++ } #Cached Remote Interactive
                "13" { $Type13Logons++ } #Cached unlock
                default { $OtherTypeLogon++ } #this shouldn't happen 出力されたらバグ
                         
            }
    
            if ($msgIpAddress -ne "-" -and             #IP Address is not blank
                !($msgTargetUserName[-1] -eq "$" -and $msgIpAddress -eq "127.0.0.1" ) -or     #Not a machine account local logon
                ($msgSubjectUserSid -eq "S-1-0-0" -and $msgTargetUserName -eq "SYSTEM")) #To find system boot time システムの起動時間を調べるため
            {
                $Timezone = Get-TimeZone
                $TimezoneName = $Timezone.DisplayName #例：(UTC+09:00 Osaka, Sapporo, Tokyo)
                $StartParen = $TimezoneName.IndexOf('(') #get position of (
                $EndParen = $TimezoneName.IndexOf(')') #position of )
                $UTCOffset = $TimezoneName.SubString( $StartParen + 1 , $EndParen - $StartParen - 1 ) # UTC+09:00
                if ( $UTC -eq $true ) {
                    $UTCOffset = "UTC"
                }

                $tempoutput = [Ordered]@{ $Create_LogonTimeline_Timezone = $UTCOffset ; $Create_LogonTimeline_LogonTime = $LogonTimestampString ; $Create_LogonTimeline_LogoffTime = $LogoffTimestampString ; $Create_LogonTimeline_ElapsedTime = $ElapsedTimeOutput ; $Create_LogonTimeline_Type = "$msgLogonType - $msgLogonTypeReadable" ; $Create_LogonTimeline_TargetUser = $msgTargetUserName ; $Create_LogonTimeline_SourceWorkstation = $msgWorkstationName ; $Create_LogonTimeline_SourceIpAddress = $msgIpAddress ; $Create_LogonTimeline_SourceIpPort = $msgIpPort ; $Create_LogonTimeline_LogonID = $msgTargetLogonID }
                
                if ( $DisplayTimezone -eq $false ) { $tempoutput.Remove($Create_LogonTimeline_Timezone) }
                if ( $ShowLogonID -eq $false ) { $tempoutput.Remove($Create_LogonTimeline_LogonID ) }

                $output += [pscustomobject]$tempoutput
    
                $TotalFilteredLogons++
                    
            }
           
        }
           
    }
    
    $LogEventDataReduction = [math]::Round( ( ($TotalLogonEvents - $TotalFilteredLogons) / $TotalLogonEvents * 100 ), 1 )

    $ProgramEndTime = Get-Date
    $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
    $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host
    Write-Host ( $Create_LogonTimeline_Processing_Time -f $RuntimeHours , $RuntimeMinutes , $RuntimeSeconds )  # "Estimated processing time: {0} hours {1} minutes {2} seconds"
    Write-Host

    $output = [System.Collections.ArrayList]$output #Make array mutable so we can delete duplicate logon events

    #重複しているログオンイベントがよくあるので、一個目（紐づいているログオフイベントがないやつ）を削除する
    for ( $i = 0 ; $i -le  ( $output.count - 1 ) ; $i++) {

        if ( $output[$i].$Create_LogonTimeline_LogonTime -eq $output[$i+1].$Create_LogonTimeline_LogonTime -and
             $output[$i].$Create_LogonTimeline_Type -eq $output[$i+1].$Create_LogonTimeline_Type -and
             $output[$i].$Create_LogonTimeline_TargetUser -eq $output[$i+1].$Create_LogonTimeline_TargetUser) {

            $output.RemoveAt($i)
            $TotalFilteredLogons--

        }

    }

    if ( $SaveOutput -eq "" ) {   
        
        if ( $OutputCSV -eq $true ) { 
            
            Write-Host 'Error: you need to specify -SaveOutput'
            Exit

        }

        if ( $OutputGUI -eq $true ) {

            $output | Out-GridView

        }
        Else {

            $output | Format-Table -AutoSize

        }
     
        Write-Host
        Write-Host $Create_LogonTimeline_Total_Logon_Event_Records -NoNewline
        Write-Host $TotalLogonEvents -ForegroundColor Cyan

        Write-Host $Create_LogonTimeline_Data_Reduction -NoNewline
        Write-Host "$LogEventDataReduction%" -ForegroundColor Cyan

        Write-Host $Create_LogonTimeline_Total_Filtered_Logons -NoNewline
        Write-Host $TotalFilteredLogons -ForegroundColor Cyan
        Write-Host

        Write-Host "$Create_LogonTimeline_Type0 " -NoNewline
        Write-Host $Type0Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type2 " -NoNewline
        Write-Host $Type2Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type3 " -NoNewline
        Write-Host $Type3Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type4 " -NoNewline
        Write-Host $Type4Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type5 " -NoNewline
        Write-Host $Type5Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type7 " -NoNewline
        Write-Host $Type7Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type8 " -NoNewline
        Write-Host $Type8Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type9 " -NoNewline
        Write-Host $Type9Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type10 " -NoNewline
        Write-Host $Type10Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type11 " -NoNewline
        Write-Host $Type11Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type12 " -NoNewline
        Write-Host $Type12Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_Type13 " -NoNewline
        Write-Host $Type13Logons -ForegroundColor Cyan

        Write-Host "$Create_LogonTimeline_TypeOther " -NoNewline
        Write-Host $OtherTypeLogon -ForegroundColor Cyan
        Write-Host
        
    }
    else {

        if ( $OutputGUI -eq $true ) { 
            
            Write-Host 'Error: you cannot output to GUI with the -SaveOutput parameter'
            Exit

        }

        if ( $OutputCSV -eq $true ) {

            $output | Export-Csv $SaveOutput

        }
        Else {

            $output | Format-Table | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Total_Logon_Event_Records $TotalLogonEvents" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Data_Reduction $LogEventDataReduction%" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Total_Filtered_Logons $TotalFilteredLogons" | Out-File $SaveOutput -Append
            Write-Output "" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type0 $Type0Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type2 $Type2Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type3 $Type3Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type4 $Type4Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type5 $Type5Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type7 $Type7Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type8 $Type8Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type9 $Type9Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type10 $Type10Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type11 $Type11Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type12 $Type12Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_Type13 $Type13Logons" | Out-File $SaveOutput -Append
            Write-Output "$Create_LogonTimeline_TypeOther $OtherTypeLogon" | Out-File $SaveOutput -Append
            Write-Output "" | Out-File $SaveOutput -Append

        }

    }
        
}

function Create-Timeline {

    if ( $LogFile -eq "" ) {

        If ( $StartTimeline -eq "" -and $EndTimeline -eq "" ) {
            #No dates specified
            $filter = "@{Logname=""Security"";ID=$EventIDsToAnalyze}"
            #$filter = @{}
            #$filter.Add("LogName", "Security")
            #$filter.Add("ID", $EventIDsToAnalyze)
        }
    
        ElseIf ( $StartTimeline -ne "" -and $EndTimeline -eq "" ) {
            #Start date specified but no end date
        
            $StartingTime = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd', $null)

            $filter = @{}
            $filter.Add("StartTime", $StartingTime)
            $filter.Add("LogName", "Security")
            #$filter.Add("ID", "4624,4625,4672,4634,4647,4720,4732,1102,4648") #filtering on IDs does not work when specifying a start date..
        
            #$filter = "@{Logname=""Security"";StartDate=$StartingTime}"
        }



        <#
    TODO: fix starttimeline and endtimeline
    If ( $StartTimeline -eq "" -and $EndTimeline -ne "" ) {  #Start date specified but no end date
        
        $StartingTime = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd', $null)

        $filter = @{}
        $filter.Add("StartTime", $StartingTime)
        $filter.Add("LogName", "Security")
        #$filter.Add("ID", "4624,4625,4672,4634,4647,4720,4732,1102,4648") #filter not working when specifying a start date..
        
        #$filter = "@{Logname=""Security"";ID=$EventIDsToAnalyze;StartTime=$yesterday;EndTime=(Get-Date)}"
    }
    #>
    

        try {
            if ( $LogFile -eq "" ) {
                Write-Host
                Write-Host "Running a live scan on the Security event log"
                Write-Host

                $logs = iex "Get-WinEvent $filter -Oldest -ErrorAction Stop"

            }
 
            #Bug: starttime not working: can filter on IDs when 
            #$filter = "@{Logname=""Security"";ID=$EventIDsToAnalyze}"
            #and $logs = iex "Get-WinEvent -FilterHashTable $filter -Oldest -ErrorAction Stop"
            #when is change to $logs Get-WinEvent -FilterHashTable $filter -Oldest -ErrorAction Stop   I get
            #Get-WinEvent error:  Cannot bind parameter 'FilterHashtable'. Cannot convert the "@{Logname="Security";ID=4624,4625,4672,4634,4647,4720,4732,1102,4648}" value of type "System.String" to type "System.Collections.Hashtable".
            #filter.add method gives me Get-WinEvent error:  Cannot bind parameter 'FilterHashtable'. Cannot convert the "System.Collections.Hashtable" value of type "System.String" to type "System.Collections.Hashtable". error when
            #$filter.Add("ID", $EventIDsToAnalyze) is specified.  
            #Get-WinEvent error:  There is not an event log on the localhost computer that matches "System.Collections.Hashtable". when commented out


        }
        catch {
            Write-Host "Get-WinEvent $filter -ErrorAction Stop"
            Write-Host "Get-WinEvent error: " $_.Exception.Message "`n"
            Write-Host "Exiting...`n"
            exit
        }       

    } 
    ElseIf ( $LogFile -ne "" ) {
        $filter = "@{Path=""$LogFile"";ID=$EventIDsToAnalyze}"
        $filter2 = "@{Path=""$LogFile""}"
        Write-Host
        Write-Host "Creating timeline for $LogFile"
        $filesize = Format-FileSize( (get-item $LogFile).length )
        Write-Host "File Size: $filesize"

        $filesizeMB = (Get-Item $LogFile).Length / 1MB
        $filesizeMB = $filesizeMB * 0.1
        $ApproxTimeInSeconds = $filesizeMB * 60
        $TempTimeSpan = New-TimeSpan -Seconds $ApproxTimeInSeconds
        $RuntimeHours = $TempTimeSpan.Hours.ToString()
        $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
        $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()
        Write-Host "Please be patient. It should take approximately: " -NoNewline
        Write-Host "$RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"

        Write-Host

        try {
            $logs = iex "Get-WinEvent $filter -Oldest -ErrorAction Stop"

        }
        catch {
            Write-Host "Get-WinEvent $filter -ErrorAction Stop"
            Write-Host "Get-WinEvent error: " $_.Exception.Message "`n"
            Write-Host "Exiting...`n"
            exit
        }
    }


    #Start reading in the logs.
    foreach ($event in $logs) {
        $TotalLogs += 1

        $printMSG = ""

        #Successful logon
        if ($event.Id -eq "4624") { 

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "LogonType" { $msgLogonType = $data.'#text' }
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "WorkstationName" { $msgWorkstationName = $data.'#text' }
                    "IpAddress" { $msgIpAddress = $data.'#text' }
                    "IpPort" { $msgIpPort = $data.'#text' }
                    "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                    default { $LogNoise += 1 }
                }
                $TotalPiecesOfData += 1
        
                $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings

                $msgIsLogonDangerous = Is-Logon-Dangerous($msgLogonType) #Check to see if the logon was dangerous (saving credentials in memory)
            }
       
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
            if ($msgTargetUserName -ne "SYSTEM" -and #Username is not system
                $msgWorkstationName -ne "-" -and #Workstation Name is not blank
                $msgIpAddress -ne "-") {
                #IP Address is not blank

                if ( $ShowLogonID -eq $true) {
                    $printMSG = " 4624 - LOGON Type $msgLogonType ($msgLogonTypeReadable) to User: $msgTargetUserName from Workstation: $msgWorkstationName IP Address: $msgIpAddress Port: $msgIpPort Logon ID: $msgTargetLogonID $msgIsLogonDangerous"
                }
                Else {
                    $printMSG = " 4624 - LOGON Type $msgLogonType ($msgLogonTypeReadable) to User: $msgTargetUserName from Workstation: $msgWorkstationName IP Address: $msgIpAddress Port: $msgIpPort $msgIsLogonDangerous"
                }


                if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                    $AlertedEvents += 1
                    if ( $SaveOutput -eq "") {
                        Write-Host $timestamp -NoNewline
                        Write-Host "  4624 - LOGON" -NoNewline -ForegroundColor $EventID_4624_Color 
                        Write-Host " Type " -NoNewline
                        Write-Host $msgLogonType -NoNewline -ForegroundColor $ParameterColor 
                        Write-Host " (" -NoNewline
                        Write-Host $msgLogonTypeReadable -NoNewline -ForegroundColor $ParameterColor
                        Write-Host ") to User: " -NoNewline 
                        Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                        Write-Host " from Workstation: " -NoNewline
                        if ( $BadWorkstations.Contains($msgWorkstationName) ) {
                            Write-Host $msgWorkstationName -NoNewline -ForegroundColor White -BackgroundColor Red
                        }
                        Else {
                            Write-Host $msgWorkstationName -NoNewline -ForegroundColor $ParameterColor
                        }
                        Write-Host " IP address: " -NoNewline
                        Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                        Write-Host " Port: " -NoNewline
                        Write-Host $msgIpPort -NoNewline -ForegroundColor $ParameterColor
                        if ( $ShowLogonID -eq $true) {
                            Write-Host " Logon ID: " -NoNewline
                            Write-Host $msgTargetLogonID -NoNewline -ForegroundColor $ParameterColor
                        } 
                        Write-Host " " -NoNewline
                        Write-Host $msgIsLogonDangerous -ForegroundColor White -BackgroundColor Red

                    }
                    Else {
                        Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                    }
                }              
            }     
        }

        #Special Logon
        if ($event.Id -eq "4672") {

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                    "SubjectUserName" { $msgSubjectUserName = $data.'#text' }
                    "SubjectLogonId" { $msgSubjectLogonId = $data.'#text' }
                    "SubjectDomainName" { 
                        $msgSubjectDomainName = $data.'#text' 
                        $LogNoise += 1
                    }  #Used just to filter noise

                    default { $LogNoise += 1 }
                    #Can also print SubjectDomainName and PrivilegeList but not including for now
                }

                $TotalPiecesOfData += 1
            
            } 

            $timestamp = $event.TimeCreated.ToString($DateFormat) 


            #Filter out SYSTEM, DWM-X, DefaultAppPool, IUSR and machine accounts (ending in $) Not using the SubectUserName anymore as an attacker could create a username as DWM-1, etc.. and bypass detection.
            <#
            if ($msgSubjectUserName -ne "SYSTEM" -and 
            $msgSubjectUserName -ne "IUSR" -and 
            $msgSubjectUserName -ne "DWM-1" -and 
            $msgSubjectUserName -ne "DWM-2" -and 
            $msgSubjectUserName -ne "DWM-3" -and 
            $msgSubjectUserName -ne "DWM-4" -and 
            $msgSubjectUserName -ne "DWM-5" -and
            $msgSubjectUserName -ne "DWM-6" -and
            $msgSubjectUserName -ne "LOCAL SERVICE" -and 
            $msgSubjectUserName -ne "NETWORK SERVICE" -and
            $msgSubjectUserName -ne "DefaultAppPool" -and
            $msgSubjectUserName[-1] -ne "$" 
            ){
                $printMSG = " 4672 - ADMIN LOGON by user: $msgSubjectUserName Logon ID: $msgSubjectLogonId"
            }
            #>

            if ($msgSubjectDomainName -ne "NT AUTHORITY" -and
                $msgSubjectDomainName -ne "Window Manager" -and 
                $msgSubjectDomainName -ne "IIS APPPOOL" -and 
                $msgSubjectUserName[-1] -ne "$" 
            ) {
                if ( $ShowLogonID -eq $true ) {
                    $printMSG = " 4672 - ADMIN LOGON by User: $msgSubjectUserName Logon ID: $msgSubjectLogonId"
                }
                else {
                    $printMSG = " 4672 - ADMIN LOGON by User: $msgSubjectUserName"
                }
            }


            if ( $previousMsg -ne $printMSG -and $printMSG -ne "" ) { 

                $AlertedEvents += 1
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4672 - ADMIN LOGON" -NoNewline -ForegroundColor $EventID_4672_Color 
                    Write-Host " by User: " -NoNewline
                    Write-Host $msgSubjectUserName -NoNewline -ForegroundColor $ParameterColor 
                    if ( $ShowLogonID -eq $true ) {
                        Write-Host " Logon ID: " -NoNewline
                        Write-Host $msgSubjectLogonId -ForegroundColor $ParameterColor
                    }
                    else {
                        Write-Host ""
                    }
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }
            }
        
        } 



        #Event 4634 - LOGOFF
        if ($event.Id -eq "4634") {

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "TargetLogonId" { $msgTargetLogonId = $data.'#text' }
                    "LogonType" { $msgLogonType = $data.'#text' } 
                    "TargetDomainName" { 
                        $LogNoise += 1
                        $msgTargetDomainName = $data.'#text' 
                    } 
                    default { $LogNoise += 1 }
                }
       
                $TotalPiecesOfData += 1
            }

            $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings
 
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
        
            if ( $ShowLogonID -eq $true ) {
                $printMSG = " 4634 - LOGOFF Type $msgLogonType ($msgLogonTypeReadable) from User: $msgTargetUserName Logon ID: $msgTargetLogonId"
            }
            Else {
                $printMSG = " 4634 - LOGOFF Type $msgLogonType ($msgLogonTypeReadable) from User: $msgTargetUserName"
            }
       

            if ($previousMsg -ne $printMSG -and $printMSG -ne "" -and 
                $msgTargetDomainName -ne "Window Manager" -and #Filter DWM-X logs
                $msgTargetDomainName -ne "Font Driver Host" -and #Filter UMFD-X logs
                $msgTargetUserName[-1] -ne "$" 
            ) {
            
                $AlertedEvents += 1

                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4634 - LOGOFF" -NoNewline -ForegroundColor $EventID_4634_Color 
                    Write-Host " Type: " -NoNewline
                    Write-Host $msgLogonType -NoNewline -ForegroundColor $ParameterColor 
                    Write-Host " (" -NoNewline
                    Write-Host $msgLogonTypeReadable -NoNewline -ForegroundColor $ParameterColor
                    Write-Host ") from User: " -NoNewline
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    if ( $ShowLogonID -eq $true ) {
                        Write-Host " Logon ID: " -NoNewline
                        Write-Host $msgTargetLogonID -ForegroundColor $ParameterColor
                    }
                    Else {
                        Write-Host ""
                    }
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }
            }     
        
        } 

        #Event 4647 - LOGOFF
        if ($event.Id -eq "4647") {

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "TargetLogonId" { $msgTargetLogonId = $data.'#text' } 
                    "TargetUserSid" { $msgTargetSid = $data.'#text' }
                    default { $LogNoise += 1 }
                }

                $TotalPiecesOfData += 1
                   
            }
       
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
       
            if ( $ShowLogonID -eq $true ) {
                $printMSG = " 4647 - LOGOFF from User: $msgTargetUserName Logon ID: $msgTargetLogonId"
            }
            Else {
                $printMSG = " 4647 - LOGOFF from User: $msgTargetUserName"
            }
              
       

            if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                $AlertedEvents += 1

                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4647 - LOGOFF" -NoNewline -ForegroundColor $EventID_4647_Color 
                    Write-Host " from User: " -NoNewline
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    if ( $ShowLogonID -eq $true ) {
                        Write-Host " Logon ID: " -NoNewline
                        Write-Host $msgTargetLogonID -ForegroundColor $ParameterColor
                    }
                    else {
                        Write-Host ""
                    }
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }  
            }    
        
        } 

        #Event 4625 - FAILED LOGON
        if ($event.Id -eq "4625") {

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "LogonType" { $msgLogonType = $data.'#text' }
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "WorkstationName" { $msgWorkstationName = $data.'#text' }
                    "IpAddress" { $msgIpAddress = $data.'#text' }
                    "IpPort" { $msgIpPort = $data.'#text' }
                    #"FailureReason" { $msgFailureReason = $data.'#text' }
                    "LogonProcessName" { $msgLogonProcessName = $data.'#text' }
                    "AuthenticationPackageName" { $msgAuthenticationPackageName = $data.'#text' }
                    "Status" { $msgStatus = $data.'#text' }
                    "SubStatus" { $msgSubStatus = $data.'#text' }
                    default { $LogNoise += 1 }
                 
                }
            }

            $TotalPiecesOfData += 1

            $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings

            <# Switching to checking status code and sub status code instead of failurereason for more granular info
            switch ( $msgFailureReason ) {
                "%%2305" { $msgFailureReasonReadable = "The specified user account has expired." }
                "%%2309" { $msgFailureReasonReadable = "The specified account's password has expired." }
                "%%2310" { $msgFailureReasonReadable = "Account currently disabled." }
                "%%2311" { $msgFailureReasonReadable = "Account logon time restriction violation." }
                "%%2312" { $msgFailureReasonReadable = "User not allowed to logon at this computer." }
                "%%2313" { $msgFailureReasonReadable = "Unknown user name or bad password." }
                default { $msgLogonTypeReadable = "Unknown" }
            }
            #>

            switch ( $msgStatus ) {
                "0xc000006d" { $msgFailureReasonReadable = "UNKNOWN USERNAME OR PASSWORD" }
                "0xc000006e" { $msgFailureReasonReadable = "UNKNOWN USERNAME OR PASSWORD" }
                "0xc000005e" { $msgFailureReasonReadable = "NO LOGON SERVERS AVAILABLE" }
                "0xc000006f" { $msgFailureReasonReadable = "OUTSIDE AUTHORIZED HOURS" }
                "0xc0000070" { $msgFailureReasonReadable = "UNAUTHORIZED WORKSTATION" }
                "0xc0000071" { $msgFailureReasonReadable = "PASSWORD EXPIRED" }
                "0xc0000072" { $msgFailureReasonReadable = "ACCOUNT DISABLED" }
                "0xc00000dc" { $msgFailureReasonReadable = "SERVER IN WRONG STATE" }
                "0xc0000133" { $msgFailureReasonReadable = "CLOCK OUT OF SYNC WITH DC" }
                "0xc000015b" { $msgFailureReasonReadable = "NO LOGON RIGHT" }
                "0xc000018c" { $msgFailureReasonReadable = "TRUST RELATIONSHIP BETWEEN PRIMARY DOMAIN AND TRUSTED DOMAIN FAILED" }
                "0xc0000192" { $msgFailureReasonReadable = "NETLOGON SERVICE NOT STARTED" }
                "0xc0000193" { $msgFailureReasonReadable = "ACCOUNT EXPIRED" }
                "0xc0000224" { $msgFailureReasonReadable = "USER REQUIRED TO CHANGE PASSWORD" }
                "0xc0000225" { $msgFailureReasonReadable = "WINDOWS BUG" }
                "0xc0000234" { $msgFailureReasonReadable = "ACCOUNT LOCKED" }
                default { $msgFailureReasonReadable = "UNKNOWN STATUS CODE: $msgStatus Please report to Yamato Security" }    

            }

            #Override the fail reason with more specific substatus
            switch ( $msgSubStatus ) {
                "0xc0000064" { $msgFailureReasonReadable = "UNKNOWN USERNAME" }
                "0xc000006a" { $msgFailureReasonReadable = "WRONG PASSWORD" }   
            }

            $timestamp = $event.TimeCreated.ToString($DateFormat) 

            $printMSG = " 4625 - FAILED LOGON Type: $msgLogonType ($msgLogonTypeReadable) from User: $msgTargetUserName Workstation: $msgWorkstationName IP Address: $msgIpAddress Port: $msgIpPort Logon Process: $msgLogonProcessName Auth: $msgAuthenticationPackageName Reason: $msgFailureReasonReadable"

            if ($previousMsg -ne $printMSG -and $printMSG -ne "" -and
                $msgTargetUserName -ne "-" ) {
                $AlertedEvents += 1
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4625 - " -NoNewline -ForegroundColor $EventID_4625_Color 
                    Write-Host "FAILED LOGON" -NoNewline -ForegroundColor White -BackgroundColor Red
                    Write-Host " Type: " -NoNewline
                    Write-Host $msgLogonType -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " (" -NoNewline
                    Write-Host $msgLogonTypeReadable -NoNewline -ForegroundColor $ParameterColor
                    Write-Host ") from User: " -NoNewline
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Workstation: " -NoNewline
                    if ( $BadWorkstations.Contains($msgWorkstationName) ) {
                        Write-Host "$msgWorkstationName" -NoNewline -ForegroundColor White -BackgroundColor Red
                    }
                    Else {
                        Write-Host $msgWorkstationName -NoNewline -ForegroundColor $ParameterColor
                    }
                    Write-Host " IP Address: " -NoNewline
                    Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Port: " -NoNewline
                    Write-Host $msgIpPort -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Logon Process: " -NoNewline 
                    Write-Host $msgLogonProcessName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Auth: " -NoNewline
                    Write-Host $msgAuthenticationPackageName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Reason: " -NoNewline
                    Write-Host $msgFailureReasonReadable -ForegroundColor White -BackgroundColor Red

                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }    
            }

        } 


        #Event 4720 - Account Created
        if ($event.Id -eq "4720") {

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "SamAccountName" { $msgSamAccountName = $data.'#text' }
                    "DisplayName" { $msgDisplayName = $data.'#text' }
                    "AccountExpires" { $msgAccountExpires = $data.'#text' }
                    "TargetSid" { $msgTargetSid = $data.'#text' }
                    default { $LogNoise += 1 }
                 
                }
                $TotalPiecesOfData += 1
                       
                if ( $msgDisplayName -eq "%%1793" ) {
                    $msgDisplayName = "<value not set>"
                }

                if ( $msgAccountExpires -eq "%%1794" ) {
                    $msgAccountExpires = "<never>"
                }
 
                $timestamp = $event.TimeCreated.ToString($DateFormat) 
                $printMSG = " 4720 - ACCOUNT CREATED User: $msgSamAccountName Display Name: $msgDisplayName Account Expires: $msgAccountExpires SID: $msgTargetSid" 

            }

            if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                $AlertedEvents += 1
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4720 - ACCOUNT CREATED" -NoNewline -ForegroundColor $EventID_4720_Color 
                    Write-Host " User: " -NoNewline
                    Write-Host $msgSamAccountName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Display Name: " -NoNewline
                    if ( $msgDisplayName -eq "<value not set>") {
                        Write-Host $msgDisplayName -NoNewline -ForegroundColor White -BackgroundColor Red
                    }
                    Else {
                        Write-Host $msgDisplayName -NoNewline -ForegroundColor $ParameterColor
                    }
                    Write-Host " Account Expires: " -NoNewline
                    if ( $msgAccountExpires -eq "<never>" ) {
                        Write-Host $msgAccountExpires -NoNewline -ForegroundColor White -BackgroundColor Red
                    }
                    Else {
                        Write-Host $msgAccountExpires -NoNewline -ForegroundColor $ParameterColor
                    }
                    Write-Host " SID: " -NoNewline
                    Write-Host $msgTargetSid -ForegroundColor $ParameterColor
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }     
            }

        }

    
        #User added a group
        if ($event.Id -eq "4732") {

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "MemberSid" { $msgMemberSid = $data.'#text' }
                    "TargetDomainName" { $msgTargetDomainName = $data.'#text' }
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "TargetSid" { $msgTargetSid = $data.'#text' } 
                    default { $LogNoise += 1 }
                }
                $TotalPiecesOfData += 1
                       
                $timestamp = $event.TimeCreated.ToString($DateFormat) 
                $group = $msgTargetDomainName
                $group += "\"
                $group += $msgTargetUserName
                $printMSG = " 4732 - USER ADDED TO GROUP User SID: $msgMemberSid was added to group: $group" 

            }
 
            if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                $AlertedEvents += 1
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4732 - USER ADDED TO GROUP" -NoNewline -ForegroundColor $EventID_4732_Color 
                    Write-Host " User SID: " -NoNewline
                    Write-Host $msgMemberSid -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " was added to group: " -NoNewline
                    if ( $msgTargetUserName -eq "Administrators" ) {
                        Write-Host $group -ForegroundColor White -BackgroundColor Red
                    }
                    Else {
                        Write-Host $group -ForegroundColor $ParameterColor
                    }
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }   
            }

        }  

        #Log cleared
        if ($event.Id -eq "1102") {

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "SubjectUserName" { $msgSubjectUserName = $data.'#text' }
                    "SubjectLogonId" { $msgSubjectLogonId = $data.'#text' }
                    default { $LogNoise += 1 }
                 
                }
                $TotalPiecesOfData += 1
            }
                  
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
            $printMSG = " 1102 - EVENT LOG CLEARED" 

            if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                $AlertedEvents += 1
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  1102 - " -NoNewline -ForegroundColor $EventID_1102_Color
                    Write-Host "EVENT LOG CLEARED" -ForegroundColor White -BackgroundColor red 
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }      
            }   
       
        }  

        #Logon using explicit credentials
        if ($event.Id -eq "4648") {
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "SubjectUserName" { $msgSubjectUserName = $data.'#text' } 
                    #"SubjectDomainName" { $msgSubjectDomainName = $data.'#text' }  #Would this be useful to add? It seems to always be the same
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "TargetDomainName" { $msgTargetDomainName = $data.'#text' }
                    "SubjectLogonId" { $msgSubjectLogonId = $data.'#text' } 
                    "TargetServerName" { $msgTargetServerName = $data.'#text' }
                    "IpAddress" { $msgIpAddress = $data.'#text' }
                    "IpPort" { $msgIpPort = $data.'#text' }
                    "ProcessName" { $msgProcessName = $data.'#text' }
                    default { $LogNoise += 1 }
                }

                $TotalPiecesOfData += 1
            }
       
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
            $isMachine = $msgSubjectUserName[-1]
       
            if ( $msgIpAddress -ne "-" -and $isMachine -ne "$") {
                #don't print local events as there are too many. also filtering machine account noise
                $AlertedEvents += 1
       
                if ( $ShowLogonID -eq $true ) {
                    $printMSG = " 4648 - EXPLICIT LOGON Subject User: $msgSubjectUserName Target User: $msgTargetUserName Target Server: $msgTargetServerName Target Domain: $msgTargetDomainName IP Address: $msgIpAddress Port: $msgIpPort Process: $msgProcessName Logon ID: $msgSubjectLogonId" 
                }
                else {
                    $printMSG = " 4648 - EXPLICIT LOGON Subject User: $msgSubjectUserName Target User: $msgTargetUserName Target Server: $msgTargetServerName Target Domain: $msgTargetDomainName IP Address: $msgIpAddress Port: $msgIpPort Process: $msgProcessName"
                }     
            }
       
       
            if ( $previousMsg -ne $printMSG -and $printMSG -ne "" ) {

                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4648 - EXPLICIT LOGON" -NoNewline -ForegroundColor $EventID_4648_Color
                    Write-Host " User: " -NoNewline
                    Write-Host $msgSubjectUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Target User: " -NoNewline
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Target Server: " -NoNewline
                    Write-Host $msgTargetServerName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Target Domain: " -NoNewline
                    Write-Host $msgTargetDomainName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " IP Address: " -NoNewline
                    Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Port: " -NoNewline
                    Write-Host $msgIpPort -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Process: " -NoNewline
                    Write-Host $msgProcessName -NoNewline  -ForegroundColor $ParameterColor
                    if ( $ShowLogonID -eq $true ) {
                        Write-Host " Logon ID: " -NoNewline
                        Write-Host $msgSubjectLogonId
                    }
                    else {
                        Write-Host ""
                    }
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                } 
            
            }
       
        } 

        if ($printMSG -ne "") {
            $previousMsg = $printMSG #Sometimes duplicate logs happen alot, so if the previous message is the same we will filter.
        }
        Else {
            $SkippedLogs += 1
        }

    }

    $GoodData = $TotalPiecesOfData - $LogNoise
    $LogEventDataReduction = [math]::Round( ( ($TotalLogs - $AlertedEvents) / $TotalLogs * 100 ), 1 )
    $PercentOfLogNoise = [math]::Round( ( $LogNoise / $TotalPiecesOfData * 100 ), 1 )
    $ProgramEndTime = Get-Date
    $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)

    Write-Host
    Write-Host "Total analyzed logs: $TotalLogs"
    Write-Host "Useless logs: $SkippedLogs"
    Write-Host "Alerted events: $AlertedEvents"
    Write-Host "Log event data reduction: $LogEventDataReduction" -NoNewline
    Write-Host "%"
    Write-Host
    Write-Host "Useful Data in filtered logs: $GoodData"
    Write-Host "Noisy Data in filtered logs: $LogNoise"
    Write-Host "Log Noise: $PercentOfLogNoise" -NoNewline
    Write-Host "%"
    Write-Host

    $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()
    Write-Output "Processing time: $RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"
}

function Perform-LiveAnalysis {
    Write-Host "perform live analyis"

}

function Perform-LiveAnalysisChecks {
    if ( $IsWindows -eq $true -or $env:OS -eq "Windows_NT" ) {
        
        #Check if running as an admin
        $isAdmin = Check-Administrator

        if ( $isAdmin -eq $false ) {
            if ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {
                Write-Host
                Write-Host "エラー： Powershellを管理者として実行する必要があります。"
                Write-Host
                Exit
            }
            else {
                Write-Host
                Write-Host "Error: You need to be running Powershell as Administrator."
                Write-Host
                Exit
            }
        }
    
    }
    else {
        #Trying to run live analysis on Mac or Linux
        if ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {
            Write-Host
            Write-Host "エラー： ライブ調査はWindowsにしか対応していません。"
            Write-Host
            Exit
        }
        else {
            Write-Host
            Write-Host "Error: Live Analysis is only supported on Windows"
            Write-Host
            Exit
        }
    }
}



#Main

if ( $ShowContributors -eq $true ) {
    Show-Contributors
    exit
}


if ( $LiveAnalysis -eq $true -and $IsDC -eq $true ) {
    if ($HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true) {
        Write-Host
        Write-Host "注意：ドメインコントローラーでライブ調査をしない方が良いです。ログをオフラインにコピーしてから解析して下さい。" -ForegroundColor White -BackgroundColor Red
        exit
    }
    Write-Host
    Write-Host "Warning: You probably should not be doing live analysis on a Domain Controller. Please copy log files offline for analysis." -ForegroundColor White -BackgroundColor Red
    exit
}

if ( $LiveAnalysis -eq $true -and $LogFile -ne "" ) {
    if ($HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true) {
        Write-Host
        Write-Host "エラー：「-LiveAnalysis `$true」 と「-LogFile」を同時に指定できません。" -ForegroundColor White -BackgroundColor Red
        exit
    }
    Write-Host
    Write-Host "Error: you cannot specify -LiveAnalysis `$true and -LogFile at the same time." -ForegroundColor White -BackgroundColor Red
    exit
}



if ( $LiveAnalysis -eq $false -and $LogFile -eq "" -and $EventIDStatistics -eq $false -and $LogonTimeline -eq $false -and $AccountInformation -eq $false -and ($HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true) ) {
 
    Write-Host 
    Write-Host "YEAセキュリティイベントタイムライン作成ツール" -ForegroundColor Green
    Write-Host "バージョン: $YEAVersion" -ForegroundColor Green
    Write-Host "作者: 白舟（田中ザック） (@yamatosecurity)" -ForegroundColor Green
    Write-Host 

    Write-Host "解析ソースを一つ指定して下さい：" 
    Write-Host "   -LiveAnalysis `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ホストOSのログでタイムラインを作成する"

    Write-Host "   -LogFile <path-to-logfile>" -NoNewline -ForegroundColor Green
    Write-Host " : オフラインの.evtxファイルでタイムラインを作成する"


    Write-Host
    Write-Host "解析タイプを一つ指定して下さい:"

    Write-Host "   -EventIDStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : イベントIDの統計情報を出力する" 

    Write-Host "   -AccountInformation `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ユーザ名とSIDのアカウント情報を出力する"

    Write-Host "   -LogonStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ログオンの統計を出力する"

    Write-Host "   -LogonTimeline `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ユーザログオンの簡単なタイムラインを出力する"

    Write-Host "   -CreateHumanReadableTimeline `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 読みやすいタイムラインを出力する"

    Write-Host 
    Write-Host "出力方法（デフォルト：標準出力）:"

    Write-Host "   -SaveOutput <出力パス>" -NoNewline -ForegroundColor Green
    Write-Host " : テキストファイルに出力する"

    Write-Host "   -OutputGUI `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Out-GridView GUIに出力する (デフォルト： `$false)"

    Write-Host "   -OutputCSV `$true" -NoNewline -ForegroundColor Green
    Write-Host " : CSVファイルに出力する (デフォルト： `$false)"

    Write-Host 
    Write-Host "解析オプション:"

    Write-Host "   -StartTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : タイムラインの始まりを指定する"

    Write-Host "   -EndTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : タイムラインの終わりを指定する"

    Write-Host "   -IsDC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ドメインコントローラーのログの場合は指定して下さい (デフォルト： `$false)"

    Write-Host 
    Write-Host "出力オプション:"

    Write-Host "   -USDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 日付をMM-DD-YYYY形式で出力する (デフォルト： YYYY-MM-DD)"

    Write-Host "   -EuropeDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 日付をDD-MM-YYYY形式で出力する (デフォルト： YYYY-MM-DD)" 

    Write-Host "   -UTC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 時間をUTC形式で出力する（デフォルト：`$false）"

    Write-Host "   -DisplayTimezone `$false" -NoNewline -ForegroundColor Green
    Write-Host " : ログオンIDを出力する (デフォルト： `$true)"

    Write-Host "   -ShowLogonID `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ログオンIDを出力する (デフォルト： `$false)"
     
    Write-Host "   -Japanese `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 日本語で出力する"

    Write-Host
    Write-Host "その他:"

    Write-Host "   -ShowContributors `$true" -NoNewline -ForegroundColor Green
    Write-Host " : コントリビューターの一覧表示" 

    Write-Host

    exit

}

if ( $LiveAnalysis -eq $false -and $LogFile -eq "" -and $EventIDStatistics -eq $false -and $LogonTimeline -eq $false -and $AccountInformation -eq $false ) {

    Write-Host 
    Write-Host "YEA Security Event Timeline Generator" -ForegroundColor Green
    Write-Host "Version: $YEAVersion" -ForegroundColor Green
    Write-Host "Author: Zach Mathis (@yamatosecurity)" -ForegroundColor Green
    Write-Host 

    Write-Host "Please specify some options:" 
    Write-Host

    Write-Host "Analysis Source (Specify one):"

    Write-Host "   -LiveAnalysis `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a timeline based on the live host's log"

    Write-Host "   -LogFile <path-to-logfile>" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a timelime from an offline .evtx file"

    Write-Host
    Write-Host "Analysis Type (Specify one):"

    Write-Host "   -EventIDStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output event ID statistics" 

    Write-Host "   -AccountInformation `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output the usernames and SIDs of accounts"
    
    Write-Host "   -LogonStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output logon statistics"

    Write-Host "   -LogonTimeline `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output a simple timeline of user logons"

    Write-Host "   -CreateBriefHumanReadableTimeline `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a human readable timeline with minimal noise"

    Write-Host "   -CreateFullHumanReadableTimeline `$true" -NoNewline  -ForegroundColor Green
    Write-Host " : Creates a human readable timeline with all details"

    Write-Host 
    Write-Host "Output Types (Default: Standard Output):"

    Write-Host "   -SaveOutput <outputfile-path>" -NoNewline -ForegroundColor Green
    Write-Host " : Output results to a text file"

    Write-Host "   -OutputCSV `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Outputs to CSV (Default: `$false)"

    Write-Host "   -OutputGUI `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Outputs to the Out-GridView GUI (Default: `$false)"

    Write-Host 
    Write-Host "Analysis Options:"

    Write-Host "   -StartTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : Specify the start of the timeline"

    Write-Host "   -EndTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : Specify the end of the timeline"

    Write-Host "   -IsDC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Specify if the logs are from a DC (Default: `$false)"

    Write-Host 
    Write-Host "Output Options:"

    Write-Host "   -USDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output the dates in MM-DD-YYYY format (Default: YYYY-MM-DD)"

    Write-Host "   -EuropeDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output the dates in DD-MM-YYYY format (Default: YYYY-MM-DD)"

    Write-Host "   -UTC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output in UTC time (Default: `$false)"
    
    Write-Host "   -DisplayTimezone `$false" -NoNewline -ForegroundColor Green
    Write-Host " : Displays the timezone used (Default: `$true)"

    Write-Host "   -ShowLogonID `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Specify if you want to see Logon IDs (Default: `$false)"

    Write-Host "   -Japanese `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output in Japanese"

    Write-Host
    Write-Host "Other:"

    Write-Host "   -ShowContributors `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Show the contributors" 


    Write-Host

    exit

}

#Create-Timeline
<#
if ( $LiveAnalysis -eq $true ) {
    Perform-LiveAnalysisChecks
}
#>

if ( $EventIDStatistics -eq $true ) {

    Create-EventIDStatistics

}

if ( $LogonTimeline -eq $true ) {

    Create-LogonTimeline

}
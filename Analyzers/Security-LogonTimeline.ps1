$EventIDsToAnalyze = "4624,4625,4672,4634,4647,4720,4732,1102,4648,4768,4769,4776"
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
# 4776 - NTLM LOGON TO LOCAL ACCOUNT

# Additional logs to filter for if a DC
# 4768 - TGT ISSUED
# 4769 - SERVICE TICKET ISSUED
# 4776 - NTLM Authentication to a local account. Suspicious on DCs.

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


function Get-KerberosStatusStr {
    param(
        $status
    )
    switch ( $status ) {
        # 数は多いが有用なデータであるかどうか確認の上追記する
        "0x0" { $msgStatusReadable = "No Error" }
        default { $msStatusReadable = "" }
    }

    return $msgStatusReadable
}

function Create-SecurityLogonTimeline {
    param([string] $UTCOffset, [string] $filePath)
    # Notes: 
    #   Logoff events without corresponding logon events first won't be printed
    #   The log service shutdown time is used for the shutdown time so might be wrong if the log service was turned off while the system was running. (anti-forensics, etc..)

    Write-Host
    Write-Host $Create_LogonTimeline_Welcome_Message #Creating a logon overview excluding service account logons, noisy local system logons and machine account logons.`nPlease be patient.
    Write-Host
    
    $WineventFilter = @{}
    $EventIDsToAnalyze = 4624, 4634, 4647, 4672, 4776, 1100, 21, 25
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

    [System.Collections.ArrayList]$output = @()
    [System.Collections.ArrayList]$LogServiceShutdownTimeArray = @()
    
    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }

    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }

    $WineventFilter.Add( "Path", $filePath )
    $filesize = Format-FileSize( (get-item $filePath).length )
    $filesizeMB = (Get-Item $filePath).length / 1MB

    $filesizeMB = $filesizeMB * 0.1
    $ApproxTimeInSeconds = $filesizeMB * 60
    $TempTimeSpan = New-TimeSpan -Seconds $ApproxTimeInSeconds
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host ( $Create_LogonTimeline_Filename -f $filePath )           # "File Name: {0}"
    Write-Host ( $Create_LogonTimeline_Filesize -f $filesize )          # "File Size: {0}"
    Write-Host ( $Create_LogonTimeline_Estimated_Processing_Time -f $RuntimeHours, $RuntimeMinutes, $RuntimeSeconds )   # "Estimated processing time: {0} hours {1} minutes {2} seconds"
    Write-Host ""
    Write-Host $Create_LogonTimeline_LoadingEVTX
    Write-Host $Create_LogonTimeline_PleaseWait
    Write-Host ""

    $logs = Get-WinEventWithFilter -WinEventFilter $WineventFilter #Load event logs into memory.
    $eventlist = @{}

    [System.Collections.ArrayList]$LogoffEventArray = @()
    [System.Collections.ArrayList]$AdminLogonArray = @()

    Write-Host $Create_LogonTimeline_AnalyzingLogs
    Write-Host ""

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
                $LogoffTimestampString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat)
            }
            else {
                $LogoffTimestampString = $event.TimeCreated.ToString($DateFormat) 
            }

            $LogoffTimestampDateTime = [datetime]::ParseExact($LogoffTimestampString, $DateFormat, $null) 
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
                $LogoffTimestampString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat)
            }
            else {
                $LogoffTimestampString = $event.TimeCreated.ToString($DateFormat) 
            }

            $LogoffTimestampDateTime = [datetime]::ParseExact($LogoffTimestampString, $DateFormat, $null) 
            $LogoffEvent = @( $msgTargetLogonID , $LogoffTimestampDateTime )
            $LogoffEventArray.Add( $LogoffEvent ) > $null

        }
            
        # 1100 Event log service stopped
        if ($event.Id -eq "1100") { 

            $TotalLogonEvents++
            $eventXML = [xml]$event.ToXml()

            if ( $UTC -eq $true ) {
                $LogServiceShutdownTimeString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat)
            }
            else {
                $LogServiceShutdownTimeString = $event.TimeCreated.ToString($DateFormat) 
            }

            $LogServiceShutdownTimeDateTime = [datetime]::ParseExact($LogServiceShutdownTimeString, $DateFormat, $null) 
            [void]$LogServiceShutdownTimeArray.Add( $LogServiceShutdownTimeDateTime )

        }

        # 4672 Special logon -> ADMIN LOGON ログオンしたユーザが管理者権限を持っているかどうか確認
        if ($event.Id -eq "4672") { 

            $TotalLogonEvents++
            $eventXML = [xml]$event.ToXml()
            
            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                    
                    "SubjectUserName" { $msgSubjectUserName = $data.'#text' } 
                    #"SubjectLogonId" { $msgSubjectLogonID = $data.'#text' }  #I was checking with Logon IDs but the duplicate 4624 event that I am filtering out later has the logon ID mapped to 4672 so will for now just check the username. 
                    #This will mess up results in the rare case that someone logs in as a normal user, adds them to the local admin group then logs in again,
                    #but will still be able to tell that that account now has admin rights or did at some point in time.

                }
            }

            if ( $AdminLogonArray.Contains( $msgSubjectUserName ) -eq $false ) {

                [void]$AdminLogonArray.Add( $msgSubjectUserName )

            }

        }
                      
    }  

    foreach ( $event in $logs ) {
        
        $outputThisEvent = $FALSE

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
                    "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                    "SubjectUserSid" { $msgSubjectUserSid = $data.'#text' } 
                    "AuthenticationPackageName" { $msgAuthPackageName = $data.'#text' }
                    "LmPackageName" { $msgLmPackageName = $data.'#text' }
                    "ProcessName" { $msgProcessName = $data.'#text' } 

                }

            }

            $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings
            $LogoffTimestampString = "" 
            $LogServiceShutdownTimeString = ""

            if ( $UTC -eq $true ) {
                $LogonTimestampString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat) 
            }
            else {
                $LogonTimestampString = $event.TimeCreated.ToString($DateFormat) 
            }

            $LogonTimestampDateTime = [datetime]::ParseExact($LogonTimestampString, $DateFormat, $null)

            if ( $msgLogonType -eq "0" ) {
                #if System startup/runtime

                foreach ( $LogServiceShutdownTime in $LogServiceShutdownTimeArray ) {

                    if ( $LogServiceShutdownTime -gt $LogonTimestampDateTime -and $LogoffTimestampString -eq "" ) {
                       
                        $LogoffTimestampString = $LogServiceShutdownTime.ToString($DateFormat) 
                        $ElapsedTime = $LogServiceShutdownTime - $LogonTimestampDateTime

                    }     
                    
                }

            }
            else {
                #regular logon events
 
                foreach ( $EventIndex in $LogoffEventArray ) {
                
                    # $EventIndex[0] -> Logoff Logon ID
                    # $EventIndex[1] -> Logoff time
                    # If the logon ID match and the logoff date is greater than the logon date and $LogoffTimestampString is blank (to prevent skipping to an older duplicate logon id (rare case?))
                    if ( $EventIndex[0] -eq $msgTargetLogonID -and $EventIndex[1] -ge $LogonTimestampDateTime -and $LogoffTimestampString -eq "" ) {
                       
                        $LogoffTimestampString = $EventIndex[1].ToString($DateFormat) 
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
    
            if ($msgIpAddress -ne "-" -and #IP Address is not blank
                !($msgTargetUserName[-1] -eq "$" -and $msgIpAddress -eq "127.0.0.1" ) -or #Not a machine account local logon
                ($msgSubjectUserSid -eq "S-1-0-0" -and $msgTargetUserName -eq "SYSTEM")) {

                $isAdmin = $AdminLogonArray.Contains( $msgTargetUserName )
                if ( $msgAuthPackageName -eq "NTLM" ) { $msgAuthPackageName = $msgLmPackageName } #NTLMの場合はv1かv2か知りたい。AuthPackageはNTLMしか書いていないので、LmPackageName (例：NTLMv1, NTLMv2）で上書きする。
                $outputThisEvent = $TRUE
            }
           
        }
        
        if ($event.Id -eq "4776") {
            
            $TotalLogonEvents++
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {

                switch ( $data.name ) {

                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "Workstation" { $msgWorkstationName = $data.'#text' }
                    "Status" { $msgStatus = $data.'#text' }

                }

            }

            $msgAuthPackageName = "NTLM"
            $msgIpAddress = "-"
            $msgProcessName = "-"

            if ( $UTC -eq $true ) {
                $LogonTimestampString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat) 
            }
            else {
                $LogonTimestampString = $event.TimeCreated.ToString($DateFormat) 
            }

            $LogonTimestampDateTime = [datetime]::ParseExact($LogonTimestampString, $DateFormat, $null)
            $LogoffTimestampString = $Create_LogonTimeline_NoLogoffEvent # "No logoff event"

            if ($msgTargetUserName[-1] -ne "$") {
                $isAdmin = $AdminLogonArray.Contains( $msgTargetUserName )
                $outputThisEvent = $TRUE
            }

        }

        #RDP logon
        if ($logs.ProviderName -eq "Microsoft-Windows-TerminalServices-LocalSessionManager") {

            if ($event.Id -eq "21" -or $event.Id -eq "25" ) {

                $TotalLogonEvents++

                $eventXML = [xml]$event.ToXml()
                
                $msgTargetUserName = $eventXML.Event.UserData.EventXML.User
                $msgTargetUserName = $msgTargetUserName.Split("\")[-1]
                $msgIpAddress = $eventXML.Event.UserData.EventXML.Address
                
                $msgWorkstationName = "-"
                $msgAuthPackageName = "-"
                $msgProcessName = "-"

                if ( $msgIpAddress -ne $Create_LogonTimeline_localComputer ) {
                    switch ( $event.Id ) {
                        "21" {
                            #RDP
                            $Type10Logons++
                            $msgLogonType = 10
                        } 
                        "25" {
                            #RDP reconnect
                            $Type7Logons++
                            $msgLogonType = 7
                        } 
                    }
                    
                    $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings                

                    if ( $UTC -eq $true ) {
                        $LogonTimestampString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat) 
                    }
                    else {
                        $LogonTimestampString = $event.TimeCreated.ToString($DateFormat) 
                    }
                    $isAdmin = $AdminLogonArray.Contains( $msgTargetUserName )                    
                    $outputThisEvent = $TRUE
                }
            }

        }
        
        if ($outputThisEvent -eq $TRUE ) {

            $tempoutput = [Ordered]@{ 
                $Create_LogonTimeline_Timezone          = $UTCOffset ;
                $Create_LogonTimeline_LogonTime         = $LogonTimestampString ;
                $Create_LogonTimeline_LogoffTime        = $LogoffTimestampString ;
                $Create_LogonTimeline_ElapsedTime       = $ElapsedTimeOutput ;
                $Create_LogonTimeline_Type              = "$msgLogonType - $msgLogonTypeReadable" ;
                $Create_LogonTimeline_Auth              = $msgAuthPackageName ;
                $Create_LogonTimeline_TargetUser        = $msgTargetUserName ;
                $Create_LogonTimeline_isAdmin           = $isAdmin ;
                $Create_LogonTimeline_SourceWorkstation = $msgWorkstationName ;
                $Create_LogonTimeline_SourceIpAddress   = $msgIpAddress ;
                "Process Name"                          = $msgProcessName ;
                $Create_LogonTimeline_LogonID           = $msgTargetLogonID
            }

            if ( $DisplayTimezone -eq $false ) { $tempoutput.Remove($Create_LogonTimeline_Timezone) }
            if ( $ShowLogonID -eq $false ) { $tempoutput.Remove($Create_LogonTimeline_LogonID ) }

            [void]$output.Add( [pscustomobject]$tempoutput )

            $TotalFilteredLogons++

        }
           
    }
    
    $LogEventDataReduction = 0;
    if ($TotalLogonEvents -ne 0) {
        $LogEventDataReduction = [math]::Round( ( ($TotalLogonEvents - $TotalFilteredLogons) / $TotalLogonEvents * 100 ), 1 )
    }

    $ProgramEndTime = Get-Date
    $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
    $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host
    Write-Host ( $Create_LogonTimeline_Processing_Time -f $RuntimeHours , $RuntimeMinutes , $RuntimeSeconds )  # "Estimated processing time: {0} hours {1} minutes {2} seconds"
    Write-Host

    #重複しているログオンイベントがよくあるので、一個目（紐づいているログオフイベントがないやつ）を削除する
    for ( $i = 0 ; $i -le ( $output.count - 1 ) ; $i++) {

        if ( $output[$i].$Create_LogonTimeline_LogonTime -eq $output[$i + 1].$Create_LogonTimeline_LogonTime -and
            $output[$i].$Create_LogonTimeline_Type -eq $output[$i + 1].$Create_LogonTimeline_Type -and
            $output[$i].$Create_LogonTimeline_TargetUser -eq $output[$i + 1].$Create_LogonTimeline_TargetUser) {

            $output.RemoveAt($i)
            $TotalFilteredLogons--

        }

    }

    if ( $SaveOutput -eq "" ) {   
        
        if ( $OutputCSV -eq $true ) { 
            Write-Host 
            Write-Host $Error_NoSaveOutputWithCSV -ForegroundColor White -BackgroundColor Red
            Write-Host 
            Exit

        }

        if ( $OutputGUI -eq $true ) {

            $output | Out-GridView

        }
        Else {

            $output | Format-Table * # Powershell by default only prints 10 columns so added *

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
            Write-Host 
            Write-Host $Error_NoNeedSaveOutputWithGUI -ForegroundColor White -BackgroundColor Red
            Write-Host 
            Exit

        }

        if ( $OutputCSV -eq $true ) {

            $output | Export-Csv $SaveOutput -Encoding UTF8

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

function Create-EasyToReadSecurityLogonTimeline {

    $filter = "@{ Path=""$LogFile""; ID=$EventIDsToAnalyze }"
    $filter2 = "@{Path = ""$LogFile"" }"
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


    #Start reading in the logs.
    foreach ($event in $logs) {
        $TotalLogs += 1

        $printMSG = ""
        # 4768 Kerberos authentication ticket(TGT) was requested
        if ($event.Id -eq "4768" -and $IsDC) {
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "ServiceName" { $msgTargetService = $data.'#text' }
                    "TargetDomainName" { $msgTargetDomainName = $data.'#text' }
                    "IPAddress" { $msgIpAddress = $data.'#text' }
                    "Status" { $msgResultCode = $data.'#text' }
                    "PreAuthType" { $msgPreAuthType = $data.'#text' }
                    default { $LogNoise += 1 }
                }
                $TotalPiecesOfData += 1
            }
            
            if ( $UTC -eq $true ) {
                $TimestampString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat)
            }
            else {
                $TimestampString = $event.TimeCreated.ToString($DateFormat) 
            }

            $TimestampDateTime = [datetime]::ParseExact($TimestampString, $DateFormat, $null) 
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
            $msgStatusReadable = Get-KerberosStatusStr $msgResultCode
            $printMSG = "4768 - Requested Kerberos authentication ticket(TGT) to Service: $msgTargetService from User: $msgTargetUserName from Domain: $msgTargetDomainName IPAddress: $msgIpAddress TicketStatus: $msgStatus($msgStatusReadable)";
            if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4768 - Requested Kerberos authentication ticket(TGT)" -NoNewline
                    Write-Host " Status " -NoNewline
                    Write-Host $msgResultCode -NoNewline -ForegroundColor $ParameterColor 
                    Write-Host " (" -NoNewline
                    Write-Host $msgStatusReadable -NoNewline -ForegroundColor $ParameterColor
                    Write-Host ") to Service: " -NoNewline 
                    Write-Host $msgTargetService -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " from User: " -NoNewline
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " from Domain: " -NoNewline
                    Write-Host $msgTargetDomainName -NoNewline -ForegroundColor $ParameterColor 
                    Write-Host " IP address: " -NoNewline
                    Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " " -NoNewline
                    Write-Host " ";
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }
            }
        }
        # 4769 Kerberos service ticket was requested
        if ($event.Id -eq "4769" -and $IsDC) {
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "ServiceName" { $msgTargetService = $data.'#text' }
                    "TargetDomainName" { $msgTargetDomainName = $data.'#text' }
                    "IPAddress" { $msgIpAddress = $data.'#text' }
                    "Status" { $msgResultCode = $data.'#text' }
                    default { $LogNoise += 1 }
                }
                $TotalPiecesOfData += 1
            }
            
            if ( $UTC -eq $true ) {
                $TimestampString = $event.TimeCreated.ToUniversalTime().ToString($DateFormat)
            }
            else {
                $TimestampString = $event.TimeCreated.ToString($DateFormat) 
            }

            $TimestampDateTime = [datetime]::ParseExact($TimestampString, $DateFormat, $null) 
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
            $msgStatusReadable = Get-KerberosStatusStr $msgResultCode
            $printMSG = "4769 - Requested Kerberos service ticket to Service: $msgTargetService from User: $msgTargetUserName IPAddress: $msgIpAddress TicketStatus: $msgStatus($msgStatusReadable)";
            if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4769 - Requested Kerberos service ticket" -NoNewline
                    Write-Host " Status " -NoNewline
                    Write-Host $msgResultCode -NoNewline -ForegroundColor $ParameterColor 
                    Write-Host " (" -NoNewline
                    Write-Host $msgStatusReadable -NoNewline -ForegroundColor $ParameterColor
                    Write-Host ") to Service: " -NoNewline 
                    Write-Host $msgTargetService -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " from User: " -NoNewline
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " IP address: " -NoNewline
                    Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " " -NoNewline
                    Write-Host "";
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }
            }            
        }
        #Successful logon
        if ($event.Id -eq "4624") { 

            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
                switch ( $data.name ) {
                    "LogonType" { $msgLogonType = $data.'#text' }
                    "TargetUserName" { $msgTargetUserName = $data.'#text' }
                    "WorkstationName" { $msgWorkstationName = $data.'#text' }
                    "IpAddress" { $msgIpAddress = $data.'#text' }
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
                    $printMSG = " 4624 - LOGON Type $msgLogonType ($msgLogonTypeReadable) to User: $msgTargetUserName from Workstation: $msgWorkstationName IP Address: $msgIpAddress Logon ID: $msgTargetLogonID $msgIsLogonDangerous"
                }
                Else {
                    $printMSG = " 4624 - LOGON Type $msgLogonType ($msgLogonTypeReadable) to User: $msgTargetUserName from Workstation: $msgWorkstationName IP Address: $msgIpAddress $msgIsLogonDangerous"
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

            $printMSG = " 4625 - FAILED LOGON Type: $msgLogonType ($msgLogonTypeReadable) from User: $msgTargetUserName Workstation: $msgWorkstationName IP Address: $msgIpAddress Auth: $msgAuthenticationPackageName Reason: $msgFailureReasonReadable"

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
                    $printMSG = " 4648 - EXPLICIT LOGON Subject User: $msgSubjectUserName Target User: $msgTargetUserName Target Server: $msgTargetServerName Target Domain: $msgTargetDomainName IP Address: $msgIpAddress Logon ID: $msgSubjectLogonId" 
                }
                else {
                    $printMSG = " 4648 - EXPLICIT LOGON Subject User: $msgSubjectUserName Target User: $msgTargetUserName Target Server: $msgTargetServerName Target Domain: $msgTargetDomainName IP Address: $msgIpAddress"
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



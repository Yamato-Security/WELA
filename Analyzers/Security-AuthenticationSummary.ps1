function Logon-Number-To-HeaderValue($msgLogonType) {
    $Header_Format = "Type{0}_({1})"
    switch ( $msgLogonType ) {
        "0" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"System") }
        "2" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"Interactive") }
        "3" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"Network") }
        "4" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"Batch") }
        "5" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"Service") }
        "7" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"Unlock") }
        "8" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"NetworkCleartext") }
        "9" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"NewCredentials") }
        "10" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"RemoteInteractive") }
        "11" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"CachedInteractive") }
        "12" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"CachedRemoteInteractive") }
        "13" { $HeaderValue = [string]::Format($Header_Format,$msgLogonType,"CachedUnlock") }
        default { $HeaderValue = "Unknown" }
    }
    return $HeaderValue
}

#Template
$Authentication_Summary_Template = @{
    User = ""
}
[System.Collections.ArrayList]$Headers = @()
$Headers = @("User")

$LogonNumbers = @(0,2,3,4,5,7,8,9,10,11,12,13,14)
foreach ($LogonNumber in $LogonNumbers) {
    $HeaderValue = Logon-Number-To-HeaderValue($LogonNumber)
    $Authentication_Summary_Template[$HeaderValue] = 0
    $Headers += $HeaderValue
}
$Authentication_EventTypes = @("Successful_Logons","BadUser_Failed_Logons","BadPassword_Failed_Logons","UnknownReason_Failed_Logons")
$Authentication_Summary = @{}
$totalEventCountNum = 0

function initialize_AuthenticationSummary {
    $totalEventCountNum = 0
    $Authentication_Summary.clear()
    foreach ( $eventType in $Authentication_EventTypes ){
        $Authentication_Summary[$eventType] = @()
    }
}

function increment_eventCount($eventType, $targetUserName, $logonType) {
    $isKnownUser = $False
    $idx = 0
    $totalEventCountNum++

    foreach ( $user_summary in $Authentication_Summary[$eventType] ) {
        If ( $user_summary["User"] -eq $targetUserName ) { $isKnownUser = $True; break }
        $idx++
    }

    $key = Logon-Number-To-HeaderValue($logonType)
    If ( $isKnownUser -eq $True ){
        $Authentication_Summary[$eventType][$idx][$key]++
    }
    else {
        $new_user = $Authentication_Summary_Template.clone()
        $new_user["User"] = $targetUserName
        $new_user[$key]++
        $Authentication_Summary[$eventType] += $new_user
    }
}

function Create-SecurityAuthenticationSummary {
    param([string] $UTCOffset, [string] $filePath)

    Write-Host
    Write-Host $Create_SecurityAuthenticationSummary_Welcome_Message
    Write-Host
    
    $WineventFilter = @{}
    $EventIDsToAnalyze = @(4624, 4625)
    $WineventFilter.Add("ID", $EventIDsToAnalyze)

    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }
    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }
    
    $filesize = Format-FileSize( (get-item $filePath).length )
    $filesizeMB = (Get-Item $filePath).length / 1MB
    $filesizeMB = $filesizeMB * 0.1
    $ApproxTimeInSeconds = $filesizeMB * 60
    $TempTimeSpan = New-TimeSpan -Seconds $ApproxTimeInSeconds
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host ( $Create_LogonTimeline_Filename -f $filePath )
    Write-Host ( $Create_LogonTimeline_Filesize -f $filesize )
    Write-Host ( $Create_LogonTimeline_Estimated_Processing_Time -f $RuntimeHours, $RuntimeMinutes, $RuntimeSeconds )   # "Estimated processing time: {0} hours {1} minutes {2} seconds"
    Write-Host ""
    Write-Host $Create_LogonTimeline_LoadingEVTX
    Write-Host $Create_LogonTimeline_PleaseWait
    Write-Host ""

    initialize_AuthenticationSummary

    $WineventFilter.Add( "Path", $filePath)
    $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest #Load event logs into memory.

    If ( $logs.length -eq 0 ) {
        Write-Host $Info_GetEventNoMatch -ForegroundColor Green
        Write-Host 
        return
    }

    Write-Host $Create_LogonTimeline_AnalyzingLogs
    Write-Host 

    foreach ( $event in $logs ) {
        $eventXML = [xml]$event.ToXml()
        $msgTargetUserName = ($eventXML.Event.EventData.Data | ? {$_.Name -eq "TargetUserName"}).'#text'
        $msgLogonType = ($eventXML.Event.EventData.Data | ? {$_.Name -eq "LogonType"}).'#text'

        #4624
        if ($event.id -eq "4624") {
            $eventType = "Successful_Logons"
        }

        #4625
        if ($event.id -eq "4625") {
            $msgFailedReason = ($eventXML.Event.EventData.Data | ? {$_.Name -eq "SubStatus"}).'#text'
            If ( $msgFailedReason -eq "0xc0000064" ) {
                $eventType = "BadUser_Failed_Logons"
            }
            elseif ( $msgFailedReason -eq "0xc000006a" ) {
                $eventType = "BadPassword_Failed_Logons"
            }
            else {
                $eventType = "UnknownReason_Failed_Logons"
            }
        }
        If ( ([int]$msgLogonType -ge 0) -and ([int]$msgLogonType -le 13) ) {
            $logonType = [int]$msgLogonType
        }
        else {
            $logonType = "Unknown"
        }
        increment_eventCount -eventType $eventType -targetUserName $msgTargetUserName -logonType $logonType
    }
    $ProgramEndTime = Get-Date
    $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
    $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host
    Write-Host ( $Create_LogonTimeline_Processing_Time -f $RuntimeHours , $RuntimeMinutes , $RuntimeSeconds )  # "Estimated processing time: {0} hours {1} minutes {2} seconds"
    Write-Host "--------------------"

    #Output
    foreach ($eventType in $Authentication_EventTypes){
        Write-Host ([string]::Format("# {0}:",$eventType))
        If ( $Authentication_Summary[$eventType].Length -eq 0 ) {
            Write-Host $Create_SecurityAuthenticationSummary_NoMatch_Message
            Write-Host 
        }
        else {
            $OutputView = $Authentication_Summary[$eventType] | % { New-Object PSCustomObject -Property $_ }
            $OutputView | Format-Table $Headers 
            if ( $OutputCSV -eq $true ) {
                $csv_filename = [string]::Format("{0}_{1}.csv", (Split-Path $filePath -Leaf), $eventType)
                $OutputView | Select-Object -Property $Headers  | Export-Csv -path $csv_filename -Encoding Default
                Write-Host ( $Create_SecurityAuthenticationSummary_OutputCSV_Message -f $csv_filename )
                Write-Host
            }

            if ( $OutputGUI -eq $true ) {
                $OutputView | Select-Object -Property $Headers | Out-GridView -title $eventType 
            }
        }
    }
}


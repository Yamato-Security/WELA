function Create-EventIDStatistics {
    param(
        [string]$filePath
    )

    Write-Host
    Write-Host $Create_EventIDStatistics_CreatingStatisticsMessage -NoNewline # "Creating Event ID Statistics for:" 
    
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

    $WineventFilter = @{}
    
    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }

    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }

    $WineventFilter.Add( "Path", $filePath ) 
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
    $filesize = Format-FileSize( (get-item $filePath).length )
    $FirstEventTimestamp = $logs[0].TimeCreated.ToString($DateFormat) 
    $LastEventTimestamp = $logs[-1].TimeCreated.ToString($DateFormat)  

    Write-Host "$Create_EventIDStatistics_TotalEventLogs $TotalNumberOfLogs" # "Total event logs: "
    Write-Host "$Create_EventIDStatistics_FileSize $filesize" # "File size: "
    Write-Host "$Create_EventIDStatistics_FirstEvent $FirstEventTimestamp" #  "First event: "
    Write-Host "$Create_EventIDStatistics_LastEvent $LastEventTimestamp" # "Last event:  "

    $sorted = $eventlist.GetEnumerator() | sort Value -Descending    #sorted gets turn into an array    
    [System.Collections.ArrayList]$ArrayWithHeader = @()
    
    for ( $i = 0 ; $i -le ( $sorted.count - 1 ) ; $i++) {
                
        $Name = $sorted[$i].Name
        $Value = $sorted[$i].Value
        $EventInfo = EventInfo($Name)
        $PercentOfLogs = [math]::Round( ( $Value / $TotalNumberOfLogs * 100 ), 1 )
        $CountPlusPercent = "$value ($PercentOfLogs%)" 
        $val = [pscustomobject]@{$Create_EventIDStatistics_Count = $CountPlusPercent ; $Create_EventIDStatistics_ID = $Name ; $Create_EventIDStatistics_Event = $EventInfo.EventTitle ; $Create_EventIDStatistics_TimelineOutput = $EventInfo.TimelineDetect } #; $Create_EventIDStatistics_Comment = $EventInfo.Comment
        $ArrayWithHeader.Add($val) > $null

    }

    $ProgramEndTime = Get-Date
    $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
    $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host
    Write-Host ( $Create_EventIDStatistics_ProcessingTime -f $RuntimeHours, $RuntimeMinutes, $RuntimeSeconds )
    Write-Host

    $ArrayWithHeader

}
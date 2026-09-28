function Get-WelaCommandParameterMap {
    # WELA.ps1 has one script-level parameter block for every subcommand. Keep
    # the semantic command surface explicit so PowerShell-bound, but unrelated,
    # parameters cannot be silently ignored before dispatch.
    $common = @('Cmd', 'Help')
    return @{
        'event-measurement'       = $common + @('MeasurementAction', 'MeasurementChannel', 'MeasurementSeconds', 'MeasurementMaximumEvents', 'MeasurementOutputPath', 'MeasurementExportEvtx')
        'dns-analytical'          = $common + @('DnsAction', 'DnsState', 'DnsRetention', 'DnsMinimumBytes', 'DnsArchiveMaximumBytes', 'AllowDnsTraceReset', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'wec-runtime'             = $common + @('WecRuntimeId', 'WecRuntimeMaximumSources', 'ResultsPath')
        'registry-sacl-recovery'  = $common + @('RegistryRecoveryAction', 'RegistryRecoveryOriginalPlanPath', 'RegistryRecoveryPendingPath', 'RegistryRecoveryConfirmedPath', 'RegistryRecoveryOriginalResultsPath', 'RegistryRecoveryPlanPath', 'RegistryRecoveryPlanHash', 'RegistryRecoveryOutputPath', 'RegistryRecoveryAllowAuditReduction', 'RegistryRecoveryAllowInheritance')
        'targeted-sacl'           = $common + @('TargetSaclAction', 'TargetSaclProfile', 'TargetSaclId', 'TargetSaclPlanPath', 'TargetSaclIncludeChildren', 'IncludeOptional', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'adcs-resume'             = $common + @('AdcsResumeAction', 'AdcsResumeJournalPath', 'AdcsResumeResultsPath', 'AdcsResumePlanPath', 'AdcsResumePlanHash', 'AdcsResumeOutputPath', 'AdcsResumeAllowRestart', 'DryRun')
        'adcs-auditing'           = $common + @('AdcsAction', 'AdcsProfile', 'AllowRestart', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'score'                   = $common + @('ScoreProfile', 'ScoreEvidencePath', 'Role', 'Build', 'IncludeOptional', 'ResultsPath', 'HtmlPath')
        'gpo-create'              = $common + @('GpoCreateAction', 'GpoCreateConfigPath', 'Auto', 'DryRun', 'BackupPath')
        'gpo-package'             = $common + @('GpoAction', 'GpoProfile', 'GpoOutputPath', 'GpoMinimumMode', 'Role', 'Build', 'IncludeOptional', 'DryRun')
        'intune-export'           = $common + @('IntuneProfile', 'IntuneBuild', 'IntuneEdition', 'IntuneOutputPath', 'IntuneMinimumMode', 'IncludeOptional')
        'evtx-recovery'           = $common + @('EvtxAction', 'EvtxProbePath', 'EvtxArchivePath', 'EvtxOutputPath')
        'registry-probe'          = $common + @('RegistryProbeAction', 'RegistryProbeOutputPath', 'RegistryProbeTimeoutSeconds')
        'file-sacl-recovery'      = $common + @('FileSaclRecoveryAction', 'FileSaclRecoveryOriginalPlanPath', 'FileSaclRecoveryPendingPath', 'FileSaclRecoveryConfirmedPath', 'FileSaclRecoveryResultsPath', 'FileSaclRecoveryPlanPath', 'FileSaclRecoveryPlanHash', 'FileSaclRecoveryOutputPath', 'Auto', 'DryRun')
        'file-access-probe'       = $common + @('FileProbeAction', 'FileProbePath', 'FileProbeOutputPath', 'FileProbeTimeoutSeconds')
        'transcription-recovery'  = $common + @('TranscriptRecoveryAction', 'TranscriptRecoveryJournalPath', 'TranscriptRecoveryOriginalResultsPath', 'TranscriptRecoveryPlanPath', 'TranscriptRecoveryPlanHash', 'TranscriptRecoveryOutputPath', 'TranscriptRecoveryAllowTemporarySuspension', 'Auto', 'DryRun')
        'audit-recovery'          = $common + @('RecoveryAction', 'RecoveryJournalPath', 'RecoveryOriginalResultsPath', 'RecoveryControlId', 'RecoveryPlanPath', 'RecoveryOutputPath', 'Auto', 'DryRun')
        'channel-recovery'        = $common + @('ChannelRecoveryAction', 'ChannelRecoveryJournalPath', 'ChannelRecoveryOriginalResultsPath', 'ChannelRecoveryChannel', 'ChannelRecoveryPlanPath', 'ChannelRecoveryPlanHash', 'ChannelRecoveryOutputPath', 'ChannelRecoveryAllowShrink', 'ChannelRecoveryAllowDisable', 'ChannelRecoveryAllowRevoke')
        'eventlog-recovery'       = $common + @('EventRecoveryAction', 'EventRecoveryJournalPath', 'EventRecoveryOriginalResultsPath', 'EventRecoveryLog', 'EventRecoveryPlanPath', 'EventRecoveryPlanHash', 'EventRecoveryOutputPath', 'EventRecoveryAllowShrink', 'EventRecoveryAllowRetentionChange')
        'wec-listener'            = $common + @('WecListenerAction', 'WecListenerComputerName', 'WecListenerLocalAddress', 'WecListenerPlanPath', 'WecListenerPlanHash', 'WecListenerOutputPath')
        'wec-ingress'             = $common + @('WecIngressAction', 'WecIngressName', 'WecIngressLocalAddress', 'WecIngressRemoteAddress', 'WecIngressPlanPath', 'WecIngressPlanHash', 'WecIngressOutputPath')
        'ntlm-auditing'           = $common + @('NtlmAuditAction', 'NtlmAuditScope', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'process-commandline'     = $common + @('ProcessCommandlineAction', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'outgoing-ntlm'           = $common + @('NtlmAction', 'OutgoingNtlmMode', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'wef-query'               = $common + @('WefQueryConfigPath', 'WefQuerySubscriptionId', 'WefQueryOutputPath', 'WefQueryMaximumEvents')
        'wec-authorization'       = $common + @('WecAuthorizationAction', 'WecAuthorizationId', 'WecAuthorizationSourceSid', 'WecAuthorizationPlanPath', 'WecAuthorizationPlanHash', 'WecAuthorizationOutputPath')
        'wec-state'               = $common + @('WecStateAction', 'WecStateId', 'WecStateSourceSid', 'WecStateDesired', 'WecStatePlanPath', 'WecStatePlanHash', 'WecStateOutputPath')
        'wec-update'              = $common + @('WecUpdateAction', 'WecUpdateId', 'WecUpdateSourceSid', 'WecUpdateQueryPath', 'WecUpdateDescription', 'WecUpdatePlanPath', 'WecUpdatePlanHash', 'WecUpdateOutputPath')
        'dns-client-probe'        = $common + @('DnsClientProbeAction', 'DnsClientProbeResolver', 'DnsClientProbeOutputPath', 'DnsClientProbeTimeoutSeconds')
        'capi2-probe'             = $common + @('Capi2ProbeAction', 'Capi2ProbeOutputPath', 'Capi2ProbeTimeoutSeconds')
        'failed-logon-probe'      = $common + @('FailedLogonAction', 'FailedLogonOutputPath', 'FailedLogonTimeoutSeconds')
        'wmi-sacl-recovery'       = $common + @('WmiRecoveryAction', 'WmiRecoveryNamespace', 'WmiRecoveryJournalPath', 'WmiRecoveryOriginalResultsPath', 'WmiRecoveryPlanPath', 'WmiRecoveryPlanHash', 'WmiRecoveryOutputPath', 'WmiRecoveryAllowAuditReduction')
        'wmi-probe'               = $common + @('WmiProbeAction', 'WmiProbeNamespace', 'WmiProbeOutputPath', 'WmiProbeTimeoutSeconds')
        'applocker-script-probe'  = $common + @('AppLockerScriptAction', 'AppLockerScriptOutputPath', 'AppLockerScriptTimeoutSeconds')
        'applocker-probe'         = $common + @('AppLockerProbeAction', 'AppLockerProbeOutputPath', 'AppLockerProbeTimeoutSeconds')
        'wef-arrival'             = $common + @('ArrivalProbePath', 'ArrivalOutputPath')
        'native-validation'       = $common + @('ProbeAction', 'ProbeOutputPath', 'ProbeTimeoutSeconds')
        'audit-integrity'         = $common + @('IntegrityAction', 'IntegrityProfile', 'AllowPrivilegeRemoval', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'retention-health'        = $common + @('RetentionConfigPath', 'RetentionPreviousPath', 'ResultsPath', 'HtmlPath')
        'control-applicability'   = $common + @('ResultsPath')
        'default-evidence'        = $common + @('DefaultEvidenceAction', 'DefaultEvidencePath', 'ResultsPath')
        'audit-notifications'     = $common + @('NotificationAction', 'NotificationControl', 'WarningPercent', 'EnablePrivacyChannel', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'rule-eligibility'        = $common + @('RuleEvidencePath', 'RuleCorpusPath', 'RuleManifestPath', 'Role', 'Build', 'ResultsPath', 'HtmlPath')
        'wef-source'              = $common + @('WefAction', 'WefConfigPath', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'wec-collector'           = $common + @('WefAction', 'WefConfigPath', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'ldap-diagnostics'        = $common + @('LdapAction', 'LdapMode', 'LdapSearchTimeMs', 'LdapExpensiveThreshold', 'LdapInefficientThreshold', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'provider-packs'          = $common + @('ProviderAction', 'ProviderPack', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'channel-read'            = $common + @('ChannelReadName', 'ChannelReadOutputPath')
        'channel-settings'        = $common + @('ChannelAction', 'ChannelProfile', 'WefQuerySet', 'GrantEventLogReaders', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'wmi-auditing'            = $common + @('WmiAction', 'WmiNamespace', 'WmiIncludeChildren', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'firewall-recovery'       = $common + @('FirewallRecoveryAction', 'FirewallRecoveryProfile', 'FirewallRecoveryJournalPath', 'FirewallRecoveryResultsPath', 'FirewallRecoveryPlanPath', 'FirewallRecoveryPlanHash', 'FirewallRecoveryOutputPath', 'Auto', 'DryRun')
        'firewall-logging'        = $common + @('FirewallAction', 'FirewallPathMode', 'FirewallMinimumSizeKiB', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'smb-runtime'             = $common + @('SmbRuntimeAction', 'SmbRuntimeOutputPath', 'Auto', 'DryRun')
        'smb-auditing'            = $common + @('SmbAction', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'powershell-logging'      = $common + @('PowerShellLoggingAction', 'PowerShellLoggingControl', 'PowerShellLoggingModuleName', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'transcript-probe'        = $common + @('TranscriptProbeAction', 'TranscriptProbeDirectory', 'TranscriptProbeOutputPath')
        'powershell-transcription' = $common + @('TranscriptionAction', 'TranscriptDirectory', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'ad-object-sacl'          = $common + @('AdSaclAction', 'AdServer', 'AdSaclProfile', 'AdObjectDn', 'AdReceiptPath', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'applocker-readiness'     = $common + @('AppLockerAction', 'AppLockerPolicyPath', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'profiles'                = $common + @('ProfileFile')
        'plan'                    = $common + @('Profile', 'ProfileFile', 'Role', 'Build', 'PlanPath', 'IncludeOptional', 'SaclMode', 'ResultsPath')
        'audit'                   = $common + @('Profile', 'ProfileFile', 'Role', 'Build', 'PlanPath', 'IncludeOptional', 'SaclMode', 'ResultsPath')
        'audit-settings'          = $common + @('OutType', 'Debug', 'Baseline', 'Profile', 'ProfileFile', 'Role', 'Build', 'PlanPath', 'IncludeOptional', 'SaclMode', 'ResultsPath', 'HtmlPath')
        'eventlog-profiles'       = $common
        'audit-filesize'          = $common + @('Baseline', 'LogProfile')
        'configure-eventlogs'     = $common + @('LogProfile', 'ResizeLogs', 'ApplyLogMode', 'Auto', 'DryRun', 'BackupPath', 'ResultsPath')
        'configure'               = $common + @('Debug', 'Baseline', 'Profile', 'ProfileFile', 'Role', 'Build', 'PlanPath', 'IncludeOptional', 'SaclMode', 'Auto', 'OutgoingNtlmMode', 'DryRun', 'BackupPath', 'ResultsPath')
        'configure-sacl'          = $common + @('Auto')
        'update-rules'            = $common
        'version'                 = $common
        'help'                    = $common
    }
}

function Assert-WelaCommandParameters {
    param(
        [string]$Command,
        [System.Collections.IDictionary]$BoundParameters,
        [System.Collections.IDictionary]$ParameterMap = (Get-WelaCommandParameterMap)
    )

    # Leave an absent or unknown command to the existing command dispatcher so
    # its established help/invalid-command behavior is unchanged.
    if ([string]::IsNullOrWhiteSpace($Command) -or -not $ParameterMap.Contains($Command)) {
        return
    }

    $allowed = @($ParameterMap[$Command])
    $unsupported = @($BoundParameters.Keys | Where-Object { $allowed -notcontains [string]$_ } | Sort-Object)
    if ($unsupported.Count -gt 0) {
        $display = @($unsupported | ForEach-Object { "-$_" }) -join ', '
        throw "Command '$Command' does not support parameter(s): $display. Check -Help for documented options; no command was run."
    }
}

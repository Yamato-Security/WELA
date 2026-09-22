# Actual Windows security-descriptor parsing, without file or policy mutation.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {Write-Host 'Skipped: Windows security descriptor runtime required.';exit 0}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/WefArrival.ps1')
. (Join-Path $repo 'scripts/FileSaclRecovery.ps1')
Initialize-WelaFileSaclRecoveryNative
$script:n=0
function Assert($Value,$Message) {if (-not $Value) {throw $Message};$script:n++}
function Throws($Action,$Pattern) {$message='';try {& $Action | Out-Null} catch {$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, received $message"}
function Encode($Descriptor) {$bytes=New-Object byte[] $Descriptor.BinaryLength;$Descriptor.GetBinaryForm($bytes,0);[Convert]::ToBase64String($bytes)}
function Clone($Descriptor) {[Security.AccessControl.RawSecurityDescriptor]::new([Convert]::FromBase64String((Encode $Descriptor)),0)}
function New-AuditAce([int]$Mask=1,[int]$Flags=64,[string]$Sid='S-1-1-0') {
    [Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]$Flags,[Security.AccessControl.AceQualifier]::SystemAudit,$Mask,[Security.Principal.SecurityIdentifier]::new($Sid),$false,$null)
}
function Add-AuditAce($Descriptor,$Ace) {
    $copy=Clone $Descriptor
    if ($null -eq $copy.SystemAcl) {$copy.SystemAcl=[Security.AccessControl.RawAcl]::new(2,1);$copy.SetFlags($copy.ControlFlags -bor [Security.AccessControl.ControlFlags]::SystemAclPresent)}
    $copy.SystemAcl.InsertAce($copy.SystemAcl.Count,$Ace)
    $copy
}
$base=[Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:(A;;FA;;;SY)')
$before=Encode $base
foreach ($flags in @(64,128,192)) {
    foreach ($sid in @('S-1-1-0','S-1-5-11')) {
        $after=Add-AuditAce $base (New-AuditAce 1 $flags $sid)
        $added=[Wela.FileSaclRecovery.Descriptor]::AddedAce($before,(Encode $after),$sid,1,$flags)
        Assert ($added -ceq [Wela.FileSaclRecovery.Descriptor]::Bytes($after.SystemAcl[0])) 'Exactly the ordinary selected ACE is identified.'
        $empty=Clone $after;$empty.SystemAcl.RemoveAce(0)
        [Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),(Encode $empty),$added)
        Assert ($empty.SystemAcl.Count -eq 0 -and ($empty.ControlFlags -band 16) -ne 0 -and (Encode $empty) -cne $before) 'ACE removal preserves an empty present SACL without claiming historical representation equality.'
        Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),$before,$added)} 'control'
        $duplicate=Add-AuditAce $after (New-AuditAce 1 $flags $sid)
        Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce($before,(Encode $duplicate),$sid,1,$flags)} 'exactly one'
        Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $duplicate),(Encode $after),$added)} 'no longer unique'
        $unrelated=Add-AuditAce $after (New-AuditAce 2 128 'S-1-5-11')
        Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce($before,(Encode $unrelated),$sid,1,$flags)} 'more than one|exactly one'
        Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),(Encode $unrelated),$added)} 'Unrelated|Unexpected'
    }
}
$old=Add-AuditAce $base (New-AuditAce 2 128 'S-1-5-11')
$after=Add-AuditAce $old (New-AuditAce)
$added=[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $old),(Encode $after),'S-1-1-0',1,64)
[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),(Encode $old),$added)
Assert ($old.SystemAcl.Count -eq 1) 'The original unrelated audit ACE remains after a valid removal.'
$lost=Add-AuditAce $base (New-AuditAce)
Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $old),(Encode $lost),'S-1-1-0',1,64)} 'original ACE'
$missing=Clone $after;$missing.SystemAcl.RemoveAce(0);$missing.SystemAcl.RemoveAce(0)
Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),(Encode $missing),$added)} 'Unrelated audit ACEs'
$covering=Add-AuditAce $base (New-AuditAce 3 64)
$redundant=Add-AuditAce $covering (New-AuditAce)
Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $covering),(Encode $redundant),'S-1-1-0',1,64)} 'already covered'
foreach ($flags in @(0,16,65,80,129,208)) {Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce($before,(Encode $after),'S-1-1-0',1,$flags)} 'explicit ordinary'}
Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce($before,(Encode $after),'S-1-5-18',1,64)} 'explicit ordinary'
Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce($before,(Encode $after),'S-1-1-0',0,64)} 'explicit ordinary'
# Both historical addition and removal must preserve non-audit descriptor fields.
foreach ($mutation in @('Owner','Group','Dacl','ControlFlags')) {
    $changed=Clone $old
    switch ($mutation) {
        Owner {$changed.Owner=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')}
        Group {$changed.Group=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')}
        Dacl {$changed.DiscretionaryAcl.RemoveAce(0)}
        ControlFlags {$changed.SetFlags($changed.ControlFlags -bor [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)}
    }
    Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),(Encode $changed),$added)} 'Owner|control|header|manager'
    $withAddition=Add-AuditAce $changed (New-AuditAce)
    Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $old),(Encode $withAddition),'S-1-1-0',1,64)} 'Owner|control|header|manager'
}
# Resource-manager control is serialized only when its valid flag is present.
$rmBefore=Clone $old;$rmBefore.SetFlags($rmBefore.ControlFlags -bor [Security.AccessControl.ControlFlags]::RMControlValid);$rmBefore.ResourceManagerControl=1
$rmAfter=Add-AuditAce $rmBefore (New-AuditAce)
$rmChanged=Clone $rmBefore;$rmChanged.ResourceManagerControl=2
Assert ((Encode $rmChanged) -cne (Encode $rmBefore)) 'RMControl fixture changes actual serialized bytes with flags unchanged.'
Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $rmAfter),(Encode $rmChanged),$added)} 'control|header'
$rmChangedAddition=Add-AuditAce $rmChanged (New-AuditAce)
Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $rmBefore),(Encode $rmChangedAddition),'S-1-1-0',1,64)} 'control|header'
# ACL revision changes cannot hide behind unchanged ACE bytes.
$revised=Clone $old;$acl4=[Security.AccessControl.RawAcl]::new(4,$revised.SystemAcl.Count)
foreach ($entry in $revised.SystemAcl) {$acl4.InsertAce($acl4.Count,$entry)}
$revised.SystemAcl=$acl4;$revisedAddition=Add-AuditAce $revised (New-AuditAce)
Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $old),(Encode $revisedAddition),'S-1-1-0',1,64)} 'revision'
Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),(Encode $revised),$added)} 'revision'
# Duplicate unrelated entries retain their exact counts.
$duplicateOld=Add-AuditAce $old (New-AuditAce 2 128 'S-1-5-11')
$duplicateAfter=Add-AuditAce $duplicateOld (New-AuditAce)
$duplicateAdded=[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $duplicateOld),(Encode $duplicateAfter),'S-1-1-0',1,64)
[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $duplicateAfter),(Encode $duplicateOld),$duplicateAdded)
Assert ($duplicateOld.SystemAcl.Count -eq 2) 'Duplicate unrelated ACEs are preserved.'
Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $duplicateAfter),(Encode $old),$duplicateAdded)} 'Unrelated audit ACEs'
# Windows can retain SACL_PRESENT with a null ACL after removing the sole ACE.
$sole=Add-AuditAce $base (New-AuditAce)
$soleAdded=[Wela.FileSaclRecovery.Descriptor]::AddedAce($before,(Encode $sole),'S-1-1-0',1,64)
$presentNull=Clone $sole;$presentNull.SystemAcl=$null
[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $sole),(Encode $presentNull),$soleAdded)
Assert ([Wela.FileSaclRecovery.Descriptor]::SaclRepresentation((Encode $presentNull)) -ceq 'PresentNull') 'Sole-ACE removal can retain present-null SACL with exact control fields.'
Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $after),(Encode $presentNull),$added)} 'lose unrelated'
Throws {[Wela.FileSaclRecovery.Descriptor]::Removed((Encode $sole),(Encode $presentNull),'different-ACE')} 'no longer unique'
# Native object audit ACEs never qualify as the ordinary selected addition.
$objectBase=Clone $base;$objectBase.SystemAcl=[Security.AccessControl.RawAcl]::new(4,0);$objectBase.SetFlags($objectBase.ControlFlags -bor [Security.AccessControl.ControlFlags]::SystemAclPresent)
$objectAfter=Clone $objectBase
$objectAce=[Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]64,[Security.AccessControl.AceQualifier]::SystemAudit,1,[Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,[guid]::NewGuid(),[guid]::Empty,$false,$null)
$objectAfter.SystemAcl.InsertAce(0,$objectAce)
Throws {[Wela.FileSaclRecovery.Descriptor]::AddedAce((Encode $objectBase),(Encode $objectAfter),'S-1-1-0',1,64)} 'exactly one'
Throws {[Wela.FileSaclRecovery.Descriptor]::Parse('not base64')} '.'
$global:LASTEXITCODE=0
Write-Host "File SACL recovery native descriptor guards: $script:n assertions passed."

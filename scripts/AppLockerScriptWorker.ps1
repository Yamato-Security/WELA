# Fixed locally generated script; no external inputs or configuration writes.
$ErrorActionPreference = 'Stop'
[Console]::Out.WriteLine(('WELA_SCRIPT_READY___WELA_SCRIPT_NONCE__|' + $ExecutionContext.SessionState.LanguageMode + '|' + $PSVersionTable.PSVersion))
$release = [Console]::In.ReadLine()
if ($release -cne 'WELA_SCRIPT_GO___WELA_SCRIPT_NONCE__') { exit 17 }
[Console]::Out.WriteLine('WELA_SCRIPT_COMPLETE___WELA_SCRIPT_NONCE__')
exit 0

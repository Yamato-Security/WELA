# Fixed locally generated script; no external inputs or configuration writes.
$ErrorActionPreference = 'Stop'
[Console]::Out.WriteLine(('WELA_SCRIPT_READY___WELA_SCRIPT_NONCE__|' + $ExecutionContext.SessionState.LanguageMode + '|' + $PSVersionTable.PSVersion))
# .NET Framework's redirected-input writer may emit an encoding preamble.
# Read the owned pipe through a BOM-aware reader, without changing console state.
$pipeReader = [IO.StreamReader]::new([Console]::OpenStandardInput(), [Text.UTF8Encoding]::new($false, $true), $true, 128, $true)
try { $release = $pipeReader.ReadLine() } finally { $pipeReader.Dispose() }
if ($release -cne 'WELA_SCRIPT_GO___WELA_SCRIPT_NONCE__') { exit 17 }
[Console]::Out.WriteLine('WELA_SCRIPT_COMPLETE___WELA_SCRIPT_NONCE__')
exit 0

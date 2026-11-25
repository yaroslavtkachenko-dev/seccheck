# Offline tests for seccheck.ps1, the Windows version.
#
# The exit address and the registry record are read from local files, toasts
# go to a file instead of the screen, and the config, state and agent configs
# live in a temp directory. Nothing in the user profile is touched. The device
# checks (BitLocker, firewall, updates) still run for real, so tests assert
# only on the rows they control. The firewall and port logic is tested on its
# own, by dot-sourcing the script's functions.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\run.ps1

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}
$ROOT = Split-Path -Parent $PSScriptRoot
$BIN = Join-Path $ROOT 'seccheck.ps1'
$PS = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"

$W = Join-Path ([IO.Path]::GetTempPath()) ('seccheck-test.' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $W, "$W\rdap", "$W\home" | Out-Null

$script:PASS = 0; $script:FAIL = 0
function ok($n) { $script:PASS++; "  ok    $n" }
function fail($n, $d) { $script:FAIL++; "  FAIL  $n"; if ($d) { "        $d" } }
function has($n, $got, $want) { if (([string]$got).Contains($want)) { ok $n } else { fail $n "wanted: $want | got: $got" } }
function hasnt($n, $got, $bad) { if (-not ([string]$got).Contains($bad)) { ok $n } else { fail $n "did not want: $bad | got: $got" } }
function eq($n, $got, $want) { if ("$got" -eq "$want") { ok $n } else { fail $n "wanted: $want | got: $got" } }

function run { $o = & $PS -NoProfile -ExecutionPolicy Bypass -File $BIN @args 2>&1 | Out-String; $script:RC = $LASTEXITCODE; $o }
function rows([string]$pattern) { ((run @args) -split "`r?`n" | Where-Object { $_ -match $pattern }) -join "`n" }
function utf8bom([string]$path, [string]$text) { [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding $true)) }

$EXIT_URI = ([Uri]"$W\exit.json").AbsoluteUri
$RDAP_URI = ([Uri]"$W\rdap").AbsoluteUri
$env:SECCHECK_CONF = "$W\conf.ps1"; $env:SECCHECK_STATE = "$W\state"; $env:SECCHECK_LOG = "$W\seccheck.log"
$env:SECCHECK_LANG = 'en'; $env:SECCHECK_NOTIFY_LOG = "$W\toast.log"; $env:SECCHECK_HOME = "$W\home"
$env:SECCHECK_TASK = 'seccheck-test'

function conf([string]$match) {  # conf <VPN_ORG_MATCH> [extra config lines…]
  utf8bom "$W\conf.ps1" ((@("`$VPN_ORG_MATCH = '$match'", "`$IP_ENDPOINTS = @('$EXIT_URI')", "`$RDAP_ENDPOINT = '$RDAP_URI'") + $args) -join "`r`n")
}
function exit_at([string]$ip, [string]$org = 'AS64500 Example Hosting') {
  [IO.File]::WriteAllText("$W\exit.json", "{`"ip`":`"$ip`",`"city`":`"Amsterdam`",`"country`":`"NL`",`"org`":`"$org`"}")
}
function exit_row { rows 'Exit point' @args }
function sent { if (Test-Path "$W\toast.log") { @(Get-Content "$W\toast.log").Count } else { 0 } }

[IO.File]::WriteAllText("$W\rdap\203.0.113.10", '{"name":"Examplenet","remarks":[{"description":["Examplenet Europe"]}]}')
[IO.File]::WriteAllText("$W\rdap\203.0.113.20", '{"name":"SOME-ISP","remarks":[{"description":["Home broadband"]}]}')
[IO.File]::WriteAllText("$W\rdap\203.0.113.21", '{"name":"SOME-ISP","remarks":[{"description":["Home broadband"]}]}')

try {

"`nbasics"
$errs = $null; [void][Management.Automation.Language.Parser]::ParseFile($BIN, [ref]$null, [ref]$errs)
eq 'script parses' $errs.Count 0
$b = [IO.File]::ReadAllBytes($BIN)
if ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { ok 'script is UTF-8 with a BOM' } else { fail 'script is UTF-8 with a BOM' 'Windows PowerShell 5.1 would read it as ANSI' }
$ver = [regex]::Match([IO.File]::ReadAllText($BIN), "\`$VERSION = '([^']+)'").Groups[1].Value
eq '--version' (run --version).Trim() "seccheck $ver"
has '--help prints usage' (run --help) 'usage: seccheck'
$null = run --no-such-flag; eq 'unknown option exits 64' $RC 64
$null = run --install-agent soon; eq 'bad agent interval exits 64' $RC 64

"`nexit point"
conf 'ExampleNet|ExampleVPN'
exit_at 203.0.113.5 'AS64501 ExampleVPN Ltd'
has 'ASN names the provider -> ok' (exit_row) '✓'

exit_at 203.0.113.5 'AS64501 examplevpn ltd'
has 'ASN match ignores case' (exit_row) '✓'

exit_at 203.0.113.10
$out = exit_row
has 'foreign ASN, registry names the provider -> ok' $out '✓'
has 'block owner is shown' $out 'block owner Examplenet'

exit_at 203.0.113.20
$out = exit_row
has 'foreign ASN, foreign registry -> problem' $out '✗'
has 'the address is shown in the alarm' $out '203.0.113.20'
$null = run; eq 'a problem makes the exit code 2' $RC 2

exit_at 203.0.113.99
has 'registry unreachable -> still a problem, no crash' (exit_row) '✗'

conf 'ExampleNet|ExampleVPN' "`$RDAP_ENDPOINT = ''"
exit_at 203.0.113.10
has 'registry disabled -> problem' (exit_row) '✗'

conf ''
exit_at 203.0.113.10
$out = exit_row
has 'no provider configured -> warning, not a pass' $out '!'
has 'the warning says what to set' $out 'VPN_ORG_MATCH'

conf 'ExampleNet|ExampleVPN' '$VPN_EXPECTED = 0'
exit_at 203.0.113.20
has 'VPN not expected -> exit point is informational' (exit_row) '✓'
hasnt 'VPN not expected -> route never alarms' (rows 'Route') '✗'

has '--no-net skips the lookup' (exit_row --no-net) 'skipped'

"`nfail-closed matching"
conf 'ExampleNet|ExampleVPN'
exit_at 203.0.113.20 'AS64502 ExampleVPNet Telecom'
has 'a longer word is not the provider' (exit_row) '✗'

[IO.File]::WriteAllText("$W\rdap\203.0.113.30", '{"name":"SOME-ISP","notices":[{"description":["Peering with ExampleVPN"]}],"links":[{"href":"https://examplevpn.example/"}]}')
exit_at 203.0.113.30
has 'provider named outside the ownership fields -> problem' (exit_row) '✗'

[IO.File]::WriteAllText("$W\rdap\203.0.113.31", '{"name":"NET-203","entities":[{"handle":"ORG-1","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","ExampleNet S.A."]]]}]}')
exit_at 203.0.113.31
has 'registrant entity names the provider -> ok' (exit_row) 'block owner ExampleNet'

[IO.File]::WriteAllText("$W\rdap\203.0.113.32", 'not json at all, but it says ExampleVPN')
exit_at 203.0.113.32
has 'unparseable registry answer -> problem' (exit_row) '✗'

exit_at '203.0.113.20/../../x'
has 'a non-address from the lookup service is not trusted' (exit_row) 'could not determine'

"`nnotifications"
conf 'ExampleNet|ExampleVPN'
Remove-Item "$W\toast.log", "$W\state" -ErrorAction SilentlyContinue
exit_at 203.0.113.20
$null = run --quiet --notify
$n1 = sent
if ($n1 -ge 1) { ok 'a new problem notifies' } else { fail 'a new problem notifies' "sent: $n1" }
$state = Get-Content "$W\state" -Raw
has 'state has the exit problem' $state 'exit:AS64500 Example Hosting'
hasnt 'state does not contain the address' $state '203.0.113'

exit_at 203.0.113.21
$null = run --quiet --notify
eq 'same problem, new address -> silent' (sent) $n1

$null = run --quiet --notify
eq 'unchanged state -> silent' (sent) $n1

$env:SECCHECK_LANG = 'uk'; $null = run --quiet --notify; $env:SECCHECK_LANG = 'en'
eq 'switching language -> silent' (sent) $n1

exit_at 203.0.113.10
$null = run --quiet --notify
hasnt 'a fixed problem leaves the state' (Get-Content "$W\state" -Raw) 'exit:'

"`nlanguage and output"
has 'English labels' (run --no-net) 'NETWORK'
$env:SECCHECK_LANG = 'uk'; $uk = run --no-net; $env:SECCHECK_LANG = 'en'
has 'Ukrainian labels' $uk 'МЕРЕЖА'
has 'Ukrainian survives the pipe' $uk 'ВІДКРИТІ ПОРТИ'
hasnt '--quiet hides passing rows' (run --quiet --no-net) '✓'

$js = run --json --no-net
try {
  $d = $js | ConvertFrom-Json
  $okRows = @($d.rows).Count -and -not @($d.rows | Where-Object { $_.status -notin 'ok', 'warn', 'bad' }).Count
  $counts = $d.failures -eq @($d.rows | Where-Object status -eq 'bad').Count -and $d.warnings -eq @($d.rows | Where-Object status -eq 'warn').Count
  if ($okRows -and $counts -and $d.platform -eq 'windows') { ok '--json is valid and consistent' } else { fail '--json is valid and consistent' $js }
} catch { fail '--json is valid and consistent' $js }

"`nconfig"
$new = "$W\fresh\seccheck.conf.ps1"
$env:SECCHECK_CONF = $new; $null = run --init-config; eq '--init-config creates the file' $RC 0
$errs = $null; [void][Management.Automation.Language.Parser]::ParseFile($new, [ref]$null, [ref]$errs)
if ((Test-Path $new) -and -not $errs.Count) { ok 'generated config is valid PowerShell' } else { fail 'generated config is valid PowerShell' }
Add-Content -LiteralPath $new -Value '# mine' -Encoding UTF8
$null = run --init-config; eq '--init-config refuses to overwrite' $RC 1
eq 'existing config is left alone' (Get-Content $new -Tail 1) '# mine'
$env:SECCHECK_CONF = "$W\conf.ps1"

"`nAI agents"
conf '' '$VPN_EXPECTED = 0'
$H = "$W\home"
New-Item -ItemType Directory -Path "$H\.claude", "$H\.codex" -Force | Out-Null
function ai([string]$pattern) { rows $pattern --no-net }

utf8bom "$H\.claude\settings.json" '{"permissions":{"defaultMode":"bypassPermissions"}}'
has 'bypass as the default mode -> problem' (ai '^\s*\S\s+Claude Code ') '✗'
has 'no deny rules -> warning' (ai 'Claude: deny') '!'

utf8bom "$H\.claude\settings.json" '{"permissions":{"disableBypassPermissionsMode":"disable","deny":["Bash(rm -rf:*)","Read(~/.ssh/**)"]}}'
$out = ai 'Claude'
has 'bypass disabled -> ok' $out 'bypass mode is disabled'
has 'deny rules are counted' $out '2 rules in permissions.deny'

utf8bom "$H\.claude\settings.json" '{"permissions": '
has 'unreadable settings -> warning, no crash' (ai 'Claude Code') 'unreadable'

utf8bom "$H\.claude\settings.json" '{}'
has 'bypass not disabled -> warning' (ai 'Claude Code') '!'

utf8bom "$H\.codex\config.toml" "sandbox_mode = `"danger-full-access`"`n"
has 'Codex without a sandbox -> problem' (ai 'Codex') '✗'
utf8bom "$H\.codex\config.toml" "approval_policy = `"never`"`n"
has 'Codex never asking -> warning' (ai 'Codex') '!'
utf8bom "$H\.codex\config.toml" "model = `"x`"`n`n[profiles.yolo]`nsandbox_mode = `"danger-full-access`"`n"
has 'only top-level Codex settings count' (ai 'Codex') 'sandbox: default'

# built here, so no scanner mistakes this file for one holding a real token
$tok = 'gh' + 'p_' + ('A1b2' * 9)
$mcp = @{ mcpServers = [ordered]@{
  github = @{ command = 'docker'; args = @('run', 'ghcr.io/github/github-mcp-server'); env = @{ GITHUB_PERSONAL_ACCESS_TOKEN = $tok } }
  ref    = @{ command = 'node'; args = @('srv.js'); env = @{ GITHUB_TOKEN = '${GITHUB_TOKEN}' } }
  fs     = @{ command = 'npx'; args = @('-y', '@modelcontextprotocol/server-filesystem', 'C:\work') }
  pinned = @{ command = 'npx'; args = @('-y', '@modelcontextprotocol/server-memory@2025.4.25') }
} }
utf8bom "$H\.claude.json" ($mcp | ConvertTo-Json -Depth 6)
utf8bom "$H\.codex\config.toml" "[mcp_servers.gl]`ncommand = `"node`"`nargs = [`"gl.js`"]`n[mcp_servers.gl.env]`nGITLAB_TOKEN = `"glpat-$('x' * 20)`"`n"
Remove-Item "$W\state" -ErrorAction SilentlyContinue
$full = run --no-net --notify
$out = ($full -split "`r?`n" | Where-Object { $_ -match 'MCP' }) -join "`n"
has 'plaintext token in an MCP config -> problem' $out 'plaintext GitHub token in .claude.json'
has 'a Codex MCP server is read too' $out 'plaintext GitLab token in .codex\config.toml'
hasnt 'an env reference is not a token' $out 'MCP: ref'
has 'npx without a version -> warning' $out '@modelcontextprotocol/server-filesystem has no pinned version'
hasnt 'npx with a version -> no warning' $out 'MCP: pinned'
hasnt 'the token is never printed' $full $tok
hasnt 'the token never reaches the state' (Get-Content "$W\state" -Raw) $tok
hasnt 'the token never reaches a notification' (Get-Content "$W\toast.log" -Raw -ErrorAction SilentlyContinue) $tok
hasnt 'the token never reaches --json' (run --json --no-net) $tok
Remove-Item "$H\.claude.json", "$H\.codex\config.toml"

"`nfirewall and ports"
$env:SECCHECK_LIB = '1'; . $BIN; Remove-Item Env:SECCHECK_LIB

function fwst($rules, [switch]$Off, [switch]$All, [switch]$Open) {
  [pscustomobject]@{ Profiles = @(4); Enabled = -not $Off; Off = @(); BlockAll = [bool]$All; DefaultBlock = -not $Open; Rules = @($rules) }
}
function rule($ports = '*', $app = '', $svc = '', [switch]$Block, $remote = '*', $proto = 6) {
  [pscustomobject]@{ Allow = -not $Block; Proto = $proto; Ports = $ports; App = $app; Svc = $svc; Remote = $remote }
}
$py = [pscustomobject]@{ Name = 'python'; Path = 'C:\py\python.exe'; Services = @(); Cmd = 'C:\py\python.exe -m http.server 8000' }
$sch = [pscustomobject]@{ Name = 'svchost'; Path = 'C:\Windows\System32\svchost.exe'; Services = @('Schedule'); Cmd = $null }
$anon = [pscustomobject]@{ Name = 'node'; Path = $null; Services = @(); Cmd = $null }

eq 'firewall off -> reachable' (Get-Reach (fwst @() -Off) 8000 $py) 'open'
eq 'default block, no rule -> blocked' (Get-Reach (fwst @()) 8000 $py) 'blocked'
eq 'default allow, no rule -> reachable' (Get-Reach (fwst @() -Open) 8000 $py) 'open'
eq 'block all inbound beats an allow rule' (Get-Reach (fwst @(rule) -All) 8000 $py) 'blocked'
eq 'allow rule for the port -> reachable' (Get-Reach (fwst @(rule '8000')) 8000 $py) 'open'
eq 'allow rule for another port -> blocked' (Get-Reach (fwst @(rule '9000')) 8000 $py) 'blocked'
eq 'port range' (Get-Reach (fwst @(rule '7000-9000')) 8000 $py) 'open'
eq 'port list' (Get-Reach (fwst @(rule '80, 8000')) 8000 $py) 'open'
eq 'local subnet only -> reachable from the LAN' (Get-Reach (fwst @(rule '8000' -remote 'LocalSubnet')) 8000 $py) 'lan'
eq 'a block rule beats an allow rule' (Get-Reach (fwst @((rule '8000'), (rule '8000' -Block))) 8000 $py) 'blocked'
eq 'a rule for another program does not apply' (Get-Reach (fwst @(rule '*' 'C:\other.exe')) 8000 $py) 'blocked'
eq 'a rule for this program applies' (Get-Reach (fwst @(rule '*' 'C:\PY\python.exe')) 8000 $py) 'open'
eq 'unknown program path -> the rule counts' (Get-Reach (fwst @(rule '*' 'C:\other.exe')) 8000 $anon) 'open'
eq 'a UDP rule does not open a TCP port' (Get-Reach (fwst @(rule '8000' -proto 17)) 8000 $py) 'blocked'
eq 'a rule for another service does not apply' (Get-Reach (fwst @(rule '*' '' 'Spooler')) 49666 $sch) 'blocked'
eq 'RPC opens the dynamic ports of an RPC service' (Get-Reach (fwst @(rule 'RPC' '' 'Schedule')) 49666 $sch) 'open'
eq 'RPC does not open a plain program' (Get-Reach (fwst @(rule 'RPC')) 49666 $py) 'blocked'
eq 'RPC-EPMap is port 135' (Test-PortSpec 'RPC-EPMap' 135 $false) 'True'

eq 'allowlisted and blocked -> ok' ((Get-PortVerdict 'blocked' $true $false) -join ',') 'ok,p_ok_blk'
eq 'not allowlisted but blocked -> warning' ((Get-PortVerdict 'blocked' $false $false) -join ',') 'warn,p_unl_blk'
eq 'not allowlisted and reachable -> problem' ((Get-PortVerdict 'open' $false $false) -join ',') 'bad,p_bad'
eq 'not allowlisted, LAN only -> problem' ((Get-PortVerdict 'lan' $false $false) -join ',') 'bad,p_bad_lan'
eq 'allowlisted but a risky service -> warning' ((Get-PortVerdict 'open' $true $true) -join ',') 'warn,p_risky'
eq 'allowlisted, ordinary service -> ok' ((Get-PortVerdict 'open' $true $false) -join ',') 'ok,p_ok_open'

eq 'a blocked RPC endpoint of any svchost service is the OS' (Test-SystemRpc 49666 'svchost' 'blocked') 'True'
eq 'a reachable one is judged like any listener' (Test-SystemRpc 49666 'svchost' 'open') 'False'
eq 'a LAN-reachable one too' (Test-SystemRpc 49666 'svchost' 'lan') 'False'
eq 'a blocked high port of a user process is not the OS' (Test-SystemRpc 50000 'python' 'blocked') 'False'
eq 'a system port below the dynamic range is not folded' (Test-SystemRpc 135 'svchost' 'blocked') 'False'

$ol = [pscustomobject]@{ Name = 'ollama'; Path = $null; Services = @(); Cmd = 'ollama serve' }
eq 'Ollama on its port is a model server' (Get-PortEntry 11434 $ol).Class 'ai'
eq 'a port number alone is not enough' ($null -eq (Get-PortEntry 11434 $anon)) 'True'
eq 'http.server is told apart from other Python' (Get-PortEntry 8000 $py).Name 'Python http.server'
$sys = [pscustomobject]@{ Name = 'System'; Path = 'System'; Services = @(); Cmd = $null }
eq 'SMB on 445 is data without a password' (Get-PortEntry 445 $sys).Class 'data'

hasnt 'a --token argument is cut out' (Clean-Cmd 'node srv.js --token=abc123 --port 3000') 'abc123'
hasnt 'a long secret-looking string is cut out' (Clean-Cmd ('app.exe ' + ('Zx9' * 14))) ('Zx9' * 14)
eq 'an ordinary command is left as is' (Clean-Cmd 'python -m http.server 8000') 'python -m http.server 8000'

eq 'an Anthropic key is not also an OpenAI key' ((Find-Tokens ('sk-' + 'ant-' + ('a' * 30))) -join ',') 'Anthropic'
eq 'an env reference is not a token' (@(Find-Tokens '${GITHUB_TOKEN}').Count) 0
eq 'npx package without a version is unpinned' (Test-Unpinned 'npx' @('-y', '@modelcontextprotocol/server-github')) 'True'
eq 'npx package with a version is pinned' (Test-Unpinned 'npx' @('-y', '@modelcontextprotocol/server-github@1.2.3')) 'False'
eq '@latest is not a pin' (Test-Unpinned 'npx.cmd' @('-y', 'some-server@latest')) 'True'
eq 'uvx with == is pinned' (Test-Unpinned 'uvx' @('mcp-server-fetch==0.6.2')) 'False'
eq 'pnpm dlx is checked too' (Test-Unpinned 'pnpm' @('dlx', 'some-server')) 'True'
eq 'a local script is not a package' (Test-Unpinned 'node' @('server.js')) 'False'

} finally {
  if ($W -like '*seccheck-test.*' -and (Test-Path $W)) { Remove-Item -LiteralPath $W -Recurse -Force }
}

"`n$PASS passed, $FAIL failed"
if ($FAIL) { exit 1 }
exit 0

# seccheck for Windows — security posture in one command: VPN tunnel, leaks,
# open ports and whether the firewall lets them in, device settings, AI agents.
# No admin rights, nothing to install: Windows PowerShell 5.1 or later.
# Exit code: 0 clean · 1 warnings · 2 problems.
# https://github.com/yaroslavtkachenko-dev/seccheck

# This file must stay UTF-8 *with* a BOM: Windows PowerShell 5.1 reads a
# script without one in the ANSI code page, and every Ukrainian label and
# every ✓ turns into mojibake.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'   # the progress bar slows Invoke-WebRequest down tenfold

$VERSION = '1.1.0'

# Output goes to pipes, files and the scheduled task's log, not only to a
# console, so the encoding is set explicitly. There may be no console at all.
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}

$SELF = $PSCommandPath

function Or($a, $b) { if ($a) { $a } else { $b } }

# Nothing is stored next to the script: it may live in a read-only or
# versioned directory.
$CONF = Or $env:SECCHECK_CONF "$env:APPDATA\seccheck\seccheck.conf.ps1"
$STATE_FILE = Or $env:SECCHECK_STATE "$env:LOCALAPPDATA\seccheck\state"
$LOG = Or $env:SECCHECK_LOG "$env:LOCALAPPDATA\seccheck\seccheck.log"
# Where agent configs are looked for. Only the tests point it elsewhere.
$HOME_DIR = Or $env:SECCHECK_HOME $env:USERPROFILE
$APPDATA_DIR = if ($env:SECCHECK_HOME) { "$HOME_DIR\AppData\Roaming" } else { $env:APPDATA }

if ((Test-Path -LiteralPath $LOG) -and (Get-Item -LiteralPath $LOG).Length -gt 524288) {
  $keep = Get-Content -LiteralPath $LOG -Tail 200 -Encoding UTF8
  [IO.File]::WriteAllLines($LOG, [string[]]$keep, (New-Object Text.UTF8Encoding $false))
}

# --- defaults (override in the config file, see --init-config) ---
$VPN_EXPECTED = 1                # 0 = no VPN in use: tunnel checks become informational
$VPN_ORG_MATCH = ''              # regex: who should own the exit IP
# Matched against the adapter's name and description. Windows has no single
# tunnel interface prefix like macOS's utun. TAP- and not TAP-Windows: VPN
# apps ship their own copy of the driver under their own name (TAP-NordVPN,
# TAP-ProtonVPN), and the adapter's name is often just "Local Area Connection".
# Only names of the VPNs' own adapters and drivers belong here, never a word
# like "VPN": an adapter seccheck does not know reads as outside the tunnel,
# so the check errs towards an alarm, never towards calm. Tried live: NordVPN
# over NordLynx and over OpenVPN (the DCO adapter).
$TUNNEL_MATCH = 'WireGuard|Wintun|TAP-|OpenVPN|Tailscale|ZeroTier|NordLynx|Mullvad|ProtonVPN|AnyConnect|Fortinet|PANGP|SonicWall|Cloudflare WARP'
# Process names, or svchost:<service> for services that share a svchost.
$ALLOWED_LISTENERS = @('System', 'lsass', 'wininit', 'services', 'spoolsv',
  'svchost:RpcSs', 'svchost:RpcEptMapper', 'svchost:CDPSvc', 'svchost:Schedule',
  'svchost:EventLog', 'svchost:iphlpsvc', 'svchost:DoSvc', 'svchost:SSDPSRV')
$IP_ENDPOINTS = @('https://ipinfo.io/json', 'https://ifconfig.co/json')
$RDAP_ENDPOINT = 'https://rdap.org/ip'   # registry: who owns an address block
$NET_TIMEOUT = 8
$UI_LANG = ''                    # "en" or "uk"; empty = follow the Windows display language

if (Test-Path -LiteralPath $CONF) { . $CONF }

# --- language ---
$UI = Or $env:SECCHECK_LANG $UI_LANG
if (-not $UI) { $UI = (Get-UICulture).Name }
$UI = if ($UI -like 'uk*') { 'uk' } else { 'en' }

if ($UI -eq 'uk') { $T = @{
  h_net        = 'МЕРЕЖА'
  h_ports      = 'ВІДКРИТІ ПОРТИ'
  h_dev        = 'ПРИСТРІЙ'
  h_ai         = 'AI-АГЕНТИ'
  l_route      = 'Маршрут'
  l_uplink     = 'Канал'
  l_profile    = 'Профіль мережі'
  l_dns        = 'DNS'
  l_ipv6       = 'IPv6'
  l_exit       = 'Точка виходу'
  l_gw         = 'Локальний шлюз'
  l_listen     = 'Слухачі'
  l_bl         = 'BitLocker'
  l_av         = 'Антивірус'
  l_fw         = 'Фаєрвол'
  l_sb         = 'Secure Boot'
  l_uac        = 'UAC'
  l_smb1       = 'SMBv1'
  l_rdp        = 'Віддалений стіл'
  l_upd        = 'Оновлення Windows'
  l_disk       = 'Місце на диску'
  l_cc         = 'Claude Code'
  l_ccdeny     = 'Claude: заборони'
  l_codex      = 'Codex'
  l_mcp        = 'MCP-сервери'
  l_ollama     = 'Ollama'
  unknown      = 'невідомо'
  route_none   = 'маршруту в інтернет нема — мережі немає'
  route_tun    = '%s — весь трафік у тунелі'
  route_out    = '%s — трафік ПОЗА тунелем'
  route_plain  = '%s — без VPN, як і налаштовано'
  uplink_ok    = '%s — %s'
  uplink_none  = 'фізичний адаптер з адресою не знайдено'
  prof_public  = '%s — «Загальнодоступна»: вхідні закриті'
  prof_private = '%s — «Приватна»: ПК видно іншим у мережі'
  prof_domain  = '%s — доменна мережа'
  dns_none     = 'DNS-сервер не визначено'
  dns_via      = '%s через %s'
  dns_out      = '%s через %s — запити ПОЗА тунелем'
  v6_none      = 'маршруту нема — витекти нічим'
  v6_tun       = '%s — у тунелі'
  v6_out       = '%s — обходить тунель'
  v6_plain     = '%s — без VPN, як і налаштовано'
  exit_skip    = 'перевірку пропущено (--no-net)'
  exit_noresp  = 'не вдалось визначити (нема відповіді)'
  exit_ok      = '%s, %s — %s'
  exit_owner   = '%s, %s — %s · блок %s'
  exit_unset   = '%s, %s — %s · провайдера не задано (VPN_ORG_MATCH)'
  exit_bad     = '%s · %s, %s — %s (не VPN!)'
  gw_none      = 'не оголошений'
  gw_up        = '%s відповідає — ти видимий у локалці'
  gw_up_plain  = '%s відповідає'
  gw_down      = '%s недосяжний — локалка відрізана'
  gw_blocked   = '%s заблокований для цього процесу — kill switch або фаєрвол'
  listen_none  = 'назовні нічого не слухає'
  p_ok_blk     = '%s — фаєрвол блокує вхідні'
  p_unl_blk    = '%s — НЕ У СПИСКУ, поки що фаєрвол блокує'
  p_ok_open    = '%s — у списку дозволених'
  p_risky      = '%s — доступний з мережі'
  p_risky_lan  = '%s — доступний з локальної мережі'
  p_bad        = '%s — НЕ У СПИСКУ, доступний з мережі'
  p_bad_lan    = '%s — НЕ У СПИСКУ, доступний з локальної мережі'
  p_unk        = 'процес не визначено (запусти від адміністратора, щоб побачити)'
  p_rpc        = 'системні RPC, портів: %s — фаєрвол блокує вхідні'
  d_pid        = 'PID %s'
  d_pid_age    = 'PID %s · слухає %s'
  d_tunnel_hint = 'якщо «%s» — твій VPN, допиши назву його адаптера в TUNNEL_MATCH (seccheck --init-config)'
  d_cmd        = 'команда: %s'
  d_risk       = 'ризик: %s'
  d_fix        = 'закрити: %s'
  age_d        = '%s дн.'
  age_h        = '%s год'
  age_m        = '%s хв'
  on           = 'увімкнено'
  off          = 'вимкнено'
  off_loud     = 'ВИМКНЕНО'
  bl_on        = '%s зашифрований'
  bl_enc       = '%s шифрується'
  bl_dec       = '%s розшифровується — захист знімають'
  bl_susp      = '%s: захист ПРИЗУПИНЕНО — ключ лежить відкрито'
  bl_wait      = '%s чекає активації — ключ лежить відкрито'
  bl_off       = '%s НЕ зашифрований'
  bl_unk       = 'стан невідомий'
  av_on        = 'Defender: захист у реальному часі'
  av_old       = 'Defender: захист у реальному часі, базам %s дн.'
  av_other     = '%s'
  fw_on        = 'усі профілі увімкнено'
  fw_part      = 'ВИМКНЕНО для: %s'
  fw_cur       = 'ВИМКНЕНО для поточної мережі (%s)'
  fw_unk       = 'стан невідомий'
  fwp_1        = 'доменна'
  fwp_2        = 'приватна'
  fwp_4        = 'загальнодоступна'
  sb_unk       = 'недоступний (старий режим BIOS)'
  uac_silent   = 'адміністратор підвищує права без запиту'
  smb1_on      = 'УВІМКНЕНО — протокол, яким ширився WannaCry'
  rdp_on       = 'увімкнено — ПК приймає віддалені підключення'
  upd_ok       = 'останнє оновлення %s дн. тому'
  upd_unk      = 'історію оновлень не прочитати'
  disk         = 'зайнято %s%%, вільно %s ГБ'
  disk_bad     = 'зайнято %s%%, вільно %s ГБ — оновлення можуть не встановитись'
  cc_default   = 'режим за замовчуванням bypassPermissions — усе без запитів'
  cc_off       = 'bypass-режим заборонено'
  cc_on        = 'bypass-режим не заборонено (permissions.disableBypassPermissionsMode)'
  cc_bad_json  = 'settings.json не читається: %s'
  cc_deny      = 'правил у permissions.deny: %s'
  cc_deny_none = 'permissions.deny порожній'
  cx_ok        = 'sandbox: %s · підтвердження: %s'
  cx_default   = 'типово'
  cx_full      = 'sandbox: danger-full-access — команди без пісочниці'
  cx_never     = 'підтвердження: never — команди без запитів'
  mcp_ok       = 'серверів: %s, відкритих токенів нема'
  mcp_token    = 'відкритий токен %s у %s'
  mcp_unpinned = '%s без зафіксованої версії — щоразу нова, неперевірена'
  ol_ok        = 'слухає лише localhost'
  ol_open      = 'OLLAMA_HOST=%s — моделі відкриті в мережу'
  sum_bad      = 'Проблем: %s'
  sum_bad_w    = ', попереджень: %s'
  sum_warn     = 'Попереджень: %s'
  sum_warn_b   = ', проблем нема'
  sum_ok       = 'Все чисто'
  n_clean      = 'чисто'
  n_clean_body = 'проблем більше нема'
  agent_ok     = 'агент встановлено, перевірка кожні %sс, лог: %s'
  agent_fail   = 'не вдалось створити завдання в Планувальнику: %s'
  agent_rm     = 'агент прибрано'
  agent_int    = 'інтервал має бути цілим числом секунд, а не «%s»'
  conf_exists  = 'конфіг уже є, не чіпаю: %s'
  conf_written = 'конфіг створено: %s'
  bad_opt      = 'невідомий параметр: %s'
  usage        = 'використання: seccheck [--quiet] [--json] [--no-net] [--notify]
       seccheck --install-agent [секунди]   фонова перевірка через Планувальник (типово 1800)
       seccheck --uninstall-agent
       seccheck --init-config               створити конфіг із поясненнями
       seccheck --version | --help
коди виходу: 0 чисто · 1 попередження · 2 проблеми
конфіг: %s'
} } else { $T = @{
  h_net        = 'NETWORK'
  h_ports      = 'OPEN PORTS'
  h_dev        = 'DEVICE'
  h_ai         = 'AI AGENTS'
  l_route      = 'Route'
  l_uplink     = 'Uplink'
  l_profile    = 'Network profile'
  l_dns        = 'DNS'
  l_ipv6       = 'IPv6'
  l_exit       = 'Exit point'
  l_gw         = 'LAN gateway'
  l_listen     = 'Listeners'
  l_bl         = 'BitLocker'
  l_av         = 'Antivirus'
  l_fw         = 'Firewall'
  l_sb         = 'Secure Boot'
  l_uac        = 'UAC'
  l_smb1       = 'SMBv1'
  l_rdp        = 'Remote Desktop'
  l_upd        = 'Windows Update'
  l_disk       = 'Disk space'
  l_cc         = 'Claude Code'
  l_ccdeny     = 'Claude: deny rules'
  l_codex      = 'Codex'
  l_mcp        = 'MCP servers'
  l_ollama     = 'Ollama'
  unknown      = 'unknown'
  route_none   = 'no route to the internet — offline'
  route_tun    = '%s — all traffic goes through the tunnel'
  route_out    = '%s — traffic BYPASSES the tunnel'
  route_plain  = '%s — no VPN, as configured'
  uplink_ok    = '%s — %s'
  uplink_none  = 'no physical adapter with an address'
  prof_public  = '%s — Public: inbound connections closed'
  prof_private = '%s — Private: this PC is discoverable on the network'
  prof_domain  = '%s — domain network'
  dns_none     = 'DNS server not found'
  dns_via      = '%s via %s'
  dns_out      = '%s via %s — queries BYPASS the tunnel'
  v6_none      = 'no route — nothing to leak'
  v6_tun       = '%s — inside the tunnel'
  v6_out       = '%s — bypasses the tunnel'
  v6_plain     = '%s — no VPN, as configured'
  exit_skip    = 'skipped (--no-net)'
  exit_noresp  = 'could not determine (no response)'
  exit_ok      = '%s, %s — %s'
  exit_owner   = '%s, %s — %s · block owner %s'
  exit_unset   = '%s, %s — %s · provider not set (VPN_ORG_MATCH)'
  exit_bad     = '%s · %s, %s — %s (not your VPN!)'
  gw_none      = 'not advertised'
  gw_up        = '%s responds — you are visible on the LAN'
  gw_up_plain  = '%s responds'
  gw_down      = '%s unreachable — LAN is cut off'
  gw_blocked   = '%s blocked for this process — kill switch or firewall'
  listen_none  = 'nothing listens on external addresses'
  p_ok_blk     = '%s — the firewall blocks inbound'
  p_unl_blk    = '%s — NOT ALLOWLISTED, the firewall blocks it for now'
  p_ok_open    = '%s — allowlisted'
  p_risky      = '%s — reachable from the network'
  p_risky_lan  = '%s — reachable from the local network'
  p_bad        = '%s — NOT ALLOWLISTED, reachable from the network'
  p_bad_lan    = '%s — NOT ALLOWLISTED, reachable from the local network'
  p_unk        = 'process unknown (run as administrator to see it)'
  p_rpc        = 'system RPC, %s ports — the firewall blocks inbound'
  d_pid        = 'PID %s'
  d_pid_age    = 'PID %s · listening for %s'
  d_tunnel_hint = "if '%s' is your VPN, add its adapter's name to TUNNEL_MATCH (seccheck --init-config)"
  d_cmd        = 'command: %s'
  d_risk       = 'risk: %s'
  d_fix        = 'fix: %s'
  age_d        = '%s d'
  age_h        = '%s h'
  age_m        = '%s min'
  on           = 'on'
  off          = 'off'
  off_loud     = 'OFF'
  bl_on        = '%s encrypted'
  bl_enc       = '%s encrypting'
  bl_dec       = '%s decrypting — protection is being removed'
  bl_susp      = '%s: protection SUSPENDED — the key is stored in the clear'
  bl_wait      = '%s waiting for activation — the key is stored in the clear'
  bl_off       = '%s NOT encrypted'
  bl_unk       = 'status unknown'
  av_on        = 'Defender: real-time protection on'
  av_old       = 'Defender: real-time protection on, definitions %s days old'
  av_other     = '%s'
  fw_on        = 'on for all profiles'
  fw_part      = 'OFF for: %s'
  fw_cur       = 'OFF for the current network (%s)'
  fw_unk       = 'status unknown'
  fwp_1        = 'domain'
  fwp_2        = 'private'
  fwp_4        = 'public'
  sb_unk       = 'not available (legacy BIOS boot)'
  uac_silent   = 'administrators are elevated without a prompt'
  smb1_on      = 'ON — the protocol WannaCry spread through'
  rdp_on       = 'on — this PC accepts remote connections'
  upd_ok       = 'last update %s days ago'
  upd_unk      = 'update history unreadable'
  disk         = '%s%% used, %s GB free'
  disk_bad     = '%s%% used, %s GB free — updates may fail to install'
  cc_default   = 'default mode is bypassPermissions — everything runs without asking'
  cc_off       = 'bypass mode is disabled'
  cc_on        = 'bypass mode is not disabled (permissions.disableBypassPermissionsMode)'
  cc_bad_json  = 'settings.json is unreadable: %s'
  cc_deny      = '%s rules in permissions.deny'
  cc_deny_none = 'permissions.deny is empty'
  cx_ok        = 'sandbox: %s · approvals: %s'
  cx_default   = 'default'
  cx_full      = 'sandbox: danger-full-access — commands run unsandboxed'
  cx_never     = 'approvals: never — commands run without asking'
  mcp_ok       = '%s servers, no plaintext tokens'
  mcp_token    = 'plaintext %s token in %s'
  mcp_unpinned = '%s has no pinned version — a new, unreviewed one every run'
  ol_ok        = 'listens on localhost only'
  ol_open      = 'OLLAMA_HOST=%s — models are open to the network'
  sum_bad      = 'Problems: %s'
  sum_bad_w    = ', warnings: %s'
  sum_warn     = 'Warnings: %s'
  sum_warn_b   = ', no problems'
  sum_ok       = 'All clear'
  n_clean      = 'all clear'
  n_clean_body = 'no problems left'
  agent_ok     = 'agent installed, checking every %ss, log: %s'
  agent_fail   = 'could not create the Task Scheduler task: %s'
  agent_rm     = 'agent removed'
  agent_int    = "the interval must be a whole number of seconds, not '%s'"
  conf_exists  = 'config already exists, left untouched: %s'
  conf_written = 'config created: %s'
  bad_opt      = 'unknown option: %s'
  usage        = 'usage: seccheck [--quiet] [--json] [--no-net] [--notify]
       seccheck --install-agent [seconds]   background check via Task Scheduler (default 1800)
       seccheck --uninstall-agent
       seccheck --init-config               write a commented config file
       seccheck --version | --help
exit codes: 0 clean · 1 warnings · 2 problems
config: %s'
} }

# --- what a port usually is, and what it costs to leave it open ---
# Class: exec = gives code execution or a session; data = data without a
# password; ai = a model server; dev = a development server; sys = a Windows
# service, named only. Exec, data and ai stay a warning even when allowlisted:
# the allowlist says "I know this process", not "this service is safe to expose".
# The second field is the process the entry is for. A port number alone is a
# hint, not proof, so an entry is used only when the owner looks right.
$PORT_META = @{
  21 = 'data|.'; 22 = 'exec|sshd'; 23 = 'exec|tlnt|telnet'; 135 = 'sys|svchost'
  139 = 'data|^System$'; 445 = 'data|^System$'; 1234 = 'ai|LM Studio|lms'
  2375 = 'exec|docker'; 3000 = 'dev|node|python|deno|bun|ruby|php|java|dotnet'
  3306 = 'data|mysql|maria'; 3389 = 'exec|svchost'; 4200 = 'dev|node'
  5000 = 'dev|python|node'; 5040 = 'sys|svchost'; 5173 = 'dev|node|bun|deno'
  5357 = 'sys|^System$'; 5432 = 'data|postgres'; 5555 = 'exec|adb'
  5900 = 'exec|vnc'; 5985 = 'exec|^System$'; 5986 = 'exec|^System$'
  6379 = 'data|redis'; 7680 = 'sys|svchost'; 7860 = 'ai|python'
  8000 = 'dev|python|node|php|uvicorn'; 8080 = 'dev|node|python|java|php'
  8188 = 'ai|python'; 8888 = 'exec|python|jupyter'; 9200 = 'data|java|elastic'
  9229 = 'exec|node'; 11211 = 'data|memcached'; 11434 = 'ai|ollama'
  27017 = 'data|mongo'
}
# name | risk | how to close it
if ($UI -eq 'uk') { $PORT_TEXT = @{
  21 = 'FTP|файли йдуть мережею відкритим текстом, часто без пароля|зупини FTP-сервер або привʼяжи його до 127.0.0.1'
  22 = 'SSH|будь-хто в мережі може пробувати увійти|якщо не користуєшся — вимкни OpenSSH Server у «Додаткових компонентах»'
  23 = 'Telnet|віддалена консоль без шифрування|видали Telnet-сервер'
  135 = 'RPC||'
  139 = 'NetBIOS|старий протокол спільного доступу, світить імʼя ПК і спільні теки|вимкни спільний доступ до файлів і принтерів для цієї мережі'
  445 = 'SMB, спільні файли|спільні теки й віддалене адміністрування з мережі|вимкни спільний доступ до файлів і принтерів для цієї мережі'
  1234 = 'сервер LM Studio|будь-хто в мережі користується твоїми моделями|LM Studio → Developer: вимкни «Serve on Local Network»'
  2375 = 'Docker API без TLS|повний контроль над Docker, а це адмін на цьому ПК|вимкни «Expose daemon on tcp://localhost:2375 without TLS»'
  3000 = 'dev-сервер|будь-хто в мережі відкриває цей застосунок і все, що він роздає|запускай із привʼязкою до 127.0.0.1'
  3306 = 'MySQL|база даних відкрита в мережу|bind-address = 127.0.0.1'
  3389 = 'Віддалений робочий стіл|вікно входу відкрите в мережу, улюблена ціль підбору паролів|Налаштування → Система → Віддалений робочий стіл: вимкнути'
  4200 = 'Angular dev-сервер|будь-хто в мережі відкриває цей застосунок|ng serve без --host 0.0.0.0'
  5000 = 'dev-сервер (Flask)|будь-хто в мережі відкриває цей застосунок|flask run без --host 0.0.0.0'
  5040 = 'CDPSvc, «Спільні пристрої»||'
  5173 = 'Vite dev-сервер|будь-хто в мережі відкриває цей застосунок|vite без --host'
  5357 = 'WSD, виявлення в мережі||'
  5432 = 'PostgreSQL|база даних відкрита в мережу|listen_addresses = ''localhost'''
  5555 = 'Android Debug Bridge|будь-хто в мережі отримує консоль на підключеному пристрої|adb usb'
  5900 = 'VNC|керування екраном з мережі|зупини VNC-сервер або привʼяжи його до 127.0.0.1'
  5985 = 'WinRM, віддалений PowerShell|сеанси PowerShell з мережі|Disable-PSRemoting у PowerShell від адміністратора'
  5986 = 'WinRM через HTTPS|сеанси PowerShell з мережі|Disable-PSRemoting у PowerShell від адміністратора'
  6379 = 'Redis|база зазвичай без пароля, її можна перетворити на виконання коду|bind 127.0.0.1 і protected-mode yes'
  7680 = 'Оптимізація доставки||'
  7860 = 'Gradio-застосунок (Stable Diffusion WebUI тощо)|будь-хто в мережі користується застосунком і твоєю відеокартою|запускай без --listen і без server_name="0.0.0.0"'
  8000 = 'dev-сервер|будь-хто в мережі відкриває цей застосунок і все, що він роздає|запускай із привʼязкою до 127.0.0.1'
  8080 = 'HTTP-сервер|будь-хто в мережі відкриває цей застосунок і все, що він роздає|привʼяжи до 127.0.0.1'
  8188 = 'ComfyUI|будь-хто в мережі запускає workflow на твоїй відеокарті|запускай без --listen'
  8888 = 'Jupyter|виконує будь-який код, який до нього дійде|jupyter lab --ip=127.0.0.1, і не вимикай токен'
  9200 = 'Elasticsearch|індекс читають і змінюють з мережі|network.host: 127.0.0.1'
  9229 = 'Node.js inspector|виконує будь-який код у цьому процесі|--inspect=127.0.0.1:9229'
  11211 = 'memcached|кеш читається з мережі, ним підсилюють DDoS|-l 127.0.0.1'
  11434 = 'Ollama|без пароля: будь-хто в мережі запускає, качає й видаляє моделі або витрачає твою квоту :cloud|setx OLLAMA_HOST 127.0.0.1, потім перезапусти Ollama'
  27017 = 'MongoDB|база часто без пароля|bindIp: 127.0.0.1'
  'http.server' = 'Python http.server|роздає файли своєї теки всім у мережі|зупини його або запускай з --bind 127.0.0.1'
} } else { $PORT_TEXT = @{
  21 = 'FTP|files cross the network in the clear, often without a password|stop the FTP server or bind it to 127.0.0.1'
  22 = 'SSH|anyone on the network can try to log in|if unused, remove OpenSSH Server in Optional features'
  23 = 'Telnet|a remote shell without encryption|remove the Telnet server'
  135 = 'RPC||'
  139 = 'NetBIOS|old sharing protocol, leaks the PC name and its shares|turn off file and printer sharing for this network'
  445 = 'SMB file sharing|shared folders and remote administration from the network|turn off file and printer sharing for this network'
  1234 = 'LM Studio server|anyone on the network uses your models|LM Studio → Developer: turn off "Serve on Local Network"'
  2375 = 'Docker API without TLS|full control of Docker, which is admin on this PC|turn off "Expose daemon on tcp://localhost:2375 without TLS"'
  3000 = 'dev server|anyone on the network opens this app and whatever it serves|start it bound to 127.0.0.1'
  3306 = 'MySQL|a database open to the network|bind-address = 127.0.0.1'
  3389 = 'Remote Desktop|a login screen open to the network, a favourite target for password guessing|Settings → System → Remote Desktop: off'
  4200 = 'Angular dev server|anyone on the network opens this app|ng serve without --host 0.0.0.0'
  5000 = 'dev server (Flask)|anyone on the network opens this app|flask run without --host 0.0.0.0'
  5040 = 'Connected Devices Platform||'
  5173 = 'Vite dev server|anyone on the network opens this app|vite without --host'
  5357 = 'WSD network discovery||'
  5432 = 'PostgreSQL|a database open to the network|listen_addresses = ''localhost'''
  5555 = 'Android Debug Bridge|anyone on the network gets a shell on the connected device|adb usb'
  5900 = 'VNC|screen control from the network|stop the VNC server or bind it to 127.0.0.1'
  5985 = 'WinRM, PowerShell remoting|PowerShell sessions from the network|Disable-PSRemoting in an elevated PowerShell'
  5986 = 'WinRM over HTTPS|PowerShell sessions from the network|Disable-PSRemoting in an elevated PowerShell'
  6379 = 'Redis|a database usually without a password, which can be turned into code execution|bind 127.0.0.1 and protected-mode yes'
  7680 = 'Delivery Optimization||'
  7860 = 'Gradio app (Stable Diffusion WebUI and others)|anyone on the network uses the app and your GPU|launch without --listen and without server_name="0.0.0.0"'
  8000 = 'dev server|anyone on the network opens this app and whatever it serves|start it bound to 127.0.0.1'
  8080 = 'HTTP server|anyone on the network opens this app and whatever it serves|bind it to 127.0.0.1'
  8188 = 'ComfyUI|anyone on the network runs workflows on your GPU|start it without --listen'
  8888 = 'Jupyter|runs any code that reaches it|jupyter lab --ip=127.0.0.1, and keep the token'
  9200 = 'Elasticsearch|an index readable and writable from the network|network.host: 127.0.0.1'
  9229 = 'Node.js inspector|runs any code inside that process|--inspect=127.0.0.1:9229'
  11211 = 'memcached|a cache readable from the network, abused for DDoS amplification|-l 127.0.0.1'
  11434 = 'Ollama|no password: anyone on the network runs, pulls and deletes models, or spends your :cloud quota|setx OLLAMA_HOST 127.0.0.1, then restart Ollama'
  27017 = 'MongoDB|a database often without a password|bindIp: 127.0.0.1'
  'http.server' = 'Python http.server|serves the files of its folder to everyone on the network|stop it, or start it with --bind 127.0.0.1'
} }

function Fmt([string]$id) {  # Fmt <message id> [args…], %s and %% as in printf
  $s = $T[$id]; if ($null -eq $s) { $s = $id }
  $sb = New-Object Text.StringBuilder; $k = 0; $n = 0
  while ($k -lt $s.Length) {
    if ($s[$k] -eq '%' -and $k + 1 -lt $s.Length) {
      if ($s[$k + 1] -eq 's') { if ($n -lt $args.Count) { [void]$sb.Append([string]$args[$n]) }; $n++; $k += 2; continue }
      if ($s[$k + 1] -eq '%') { [void]$sb.Append('%'); $k += 2; continue }
    }
    [void]$sb.Append($s[$k]); $k++
  }
  $sb.ToString()
}

# --- Task Scheduler agent ---
$AGENT_TASK = Or $env:SECCHECK_TASK 'io.github.yaroslavtkachenko-dev.seccheck'

function Install-Agent($interval) {
  if (-not $interval) { $interval = '1800' }
  if ($interval -notmatch '^\d+$') { [Console]::Error.WriteLine((Fmt agent_int $interval)); return 64 }
  # Task Scheduler repeats at most once a minute
  $sec = [Math]::Max(60, [int]$interval)
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LOG) | Out-Null
  # A scheduled powershell.exe flashes a console window on every run, even
  # with -WindowStyle Hidden. conhost --headless gives it no window at all.
  # Windows PowerShell, not pwsh: only it can show a toast without a module.
  $ps = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
  $arg = "--headless `"$ps`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$SELF`" --quiet --notify --log"
  try {
    $action = New-ScheduledTaskAction -Execute "$env:windir\System32\conhost.exe" -Argument $arg
    $every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Seconds $sec)
    $logon = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
      -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $AGENT_TASK -Action $action -Trigger $every, $logon -Settings $set `
      -Description 'seccheck: security posture check, notifies on a change' -Force -ErrorAction Stop | Out-Null
  } catch {
    [Console]::Out.WriteLine((Fmt agent_fail $_.Exception.Message)); return 1
  }
  [Console]::Out.WriteLine((Fmt agent_ok $sec $LOG)); 0
}

function Uninstall-Agent {
  Unregister-ScheduledTask -TaskName $AGENT_TASK -Confirm:$false -ErrorAction SilentlyContinue
  [Console]::Out.WriteLine($T.agent_rm); 0
}

function Init-Config {
  if (Test-Path -LiteralPath $CONF) { [Console]::Out.WriteLine((Fmt conf_exists $CONF)); return 1 }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $CONF) | Out-Null
  $text = @'
# seccheck config. Dot-sourced as PowerShell on every run; delete a line to get the default.

# 1 = you use a VPN and a missing tunnel is a problem.
# 0 = no VPN: route, DNS, IPv6 and exit point are shown but never alarm.
$VPN_EXPECTED = 1

# Regex (case-insensitive, whole words) naming who should own your exit IP. It
# is matched against the exit ASN name and, if that fails, against the registry
# record of the address block (its name, remarks and entity names), because
# providers often announce their own blocks through somebody else's network.
# To find yours: connect the VPN, run seccheck, read the "Exit point" row, then
# look at  Invoke-RestMethod https://rdap.org/ip/<that address>
# Example: 'ExampleVPN|Example Networks' (the brand, plus the company its
# address blocks are registered to).
# Empty = the exit point is shown but cannot be verified (a warning).
$VPN_ORG_MATCH = ''

# Regex matched against the adapter name and description to recognise a
# tunnel. Add your VPN's adapter if seccheck does not recognise it:
#   Get-NetAdapter | Select-Object Name, InterfaceDescription
$TUNNEL_MATCH = 'WireGuard|Wintun|TAP-|OpenVPN|Tailscale|ZeroTier|NordLynx|Mullvad|ProtonVPN|AnyConnect|Fortinet|PANGP|SonicWall|Cloudflare WARP'

# Processes allowed to listen on non-loopback addresses. A service hosted in
# a shared svchost is named svchost:<service>. Anything else that listens is a
# warning while the firewall blocks it and a problem once the network can reach it.
#   System             SMB, NetBIOS and HTTP.sys listeners
#   lsass, wininit, services, spoolsv, svchost:Schedule, svchost:EventLog
#                      dynamic RPC endpoints (ports 49152 and up)
#   svchost:RpcSs, svchost:RpcEptMapper   RPC endpoint mapper (135)
#   svchost:CDPSvc     Connected Devices Platform (5040)
#   svchost:DoSvc      Delivery Optimization (7680)
$ALLOWED_LISTENERS = @('System', 'lsass', 'wininit', 'services', 'spoolsv',
  'svchost:RpcSs', 'svchost:RpcEptMapper', 'svchost:CDPSvc', 'svchost:Schedule',
  'svchost:EventLog', 'svchost:iphlpsvc', 'svchost:DoSvc', 'svchost:SSDPSRV')

# Where to ask for the public address. The first one that answers is used.
$IP_ENDPOINTS = @('https://ipinfo.io/json', 'https://ifconfig.co/json')

# Address registry (RDAP), asked only when the exit ASN does not match.
# Empty disables that second look.
$RDAP_ENDPOINT = 'https://rdap.org/ip'

# Timeout for each network request, seconds.
$NET_TIMEOUT = 8

# Output language: 'en' or 'uk'. Empty = follow the Windows display language.
$UI_LANG = ''
'@
  # a here-string has no final newline, and a line the user appends would
  # otherwise join the last setting
  [IO.File]::WriteAllText($CONF, $text + "`r`n", (New-Object Text.UTF8Encoding $true))
  [Console]::Out.WriteLine((Fmt conf_written $CONF)); 0
}

# --- network helpers ---
function Fetch([string]$url, [switch]$HttpsOnly) {  # body of a URL, or $null
  try {
    $u = [Uri]$url
    if ($u.Scheme -eq 'file') {
      if (Test-Path -LiteralPath $u.LocalPath -PathType Leaf) { return Get-Content -LiteralPath $u.LocalPath -Raw -Encoding UTF8 }
      return $null
    }
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $NET_TIMEOUT -MaximumRedirection 3 -ErrorAction Stop
    # rdap.org redirects to the regional registry; follow it, but only over https
    if ($HttpsOnly -and $r.BaseResponse.ResponseUri.Scheme -ne 'https') { return $null }
    # The raw bytes, decoded as UTF-8: without a charset in the header Windows
    # PowerShell decodes as Latin-1 (Košice becomes KoÅ¡ice), and an
    # application/rdap+json body does not come back as text at all.
    [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray())
  } catch { $null }
}

function Is-Ip([string]$s) { $s -match '^([0-9]{1,3}\.){3}[0-9]{1,3}$' -or $s -match '^[0-9A-Fa-f]*:[0-9A-Fa-f:.]*$' }

function Vpn-Match([string]$s) {  # what matched if $s names the VPN provider: whole words, any case
  if (-not $VPN_ORG_MATCH -or -not $s) { return $null }
  # Whole words only, so that a short pattern cannot pass on a longer,
  # unrelated name. This check has to fail closed.
  $m = [regex]::Match($s, "(?:^|[^\p{L}\p{Nd}])(?<m>$VPN_ORG_MATCH)(?:$|[^\p{L}\p{Nd}])", 'IgnoreCase')
  if ($m.Success) { $m.Groups['m'].Value }
}

# The fields of a registry record that say whose block it is: the network
# name, its remarks and the names of the entities attached to it. Matching the
# whole response instead would let a stray word in a notice or a link pass for
# the provider.
function Rdap-Owners($o) {
  if ($o.name) { [string]$o.name }
  foreach ($r in @($o.remarks)) { foreach ($d in @($r.description)) { if ($d) { [string]$d } } }
  foreach ($e in @($o.entities)) {
    $v = $e.vcardArray
    if ($v -and $v.Count -ge 2) {
      foreach ($f in @($v[1])) { if ($f -and $f[0] -eq 'fn') { [string]$f[3]; break } }
    }
  }
}

function Clean([string]$s) { ($s -replace '[\x00-\x1f\x7f]', '').Trim() }

# --- firewall: is a listener reachable, or does the firewall drop it? ---
# Read through the HNetCfg COM object, which needs no admin rights and returns
# all ~900 rules in a fraction of a second, unlike Get-NetFirewallRule with
# its per-rule filter lookups.
# The Wi-Fi Direct rules let the System process and CDPSvc in on any port.
# They are there for the Wi-Fi Direct virtual adapter, not for the network the
# PC is on, but nothing in a rule says so in a form this script can read, and
# counted as global they would show SMB as open on every Windows PC. They are
# known by their ids (WiFiDirect-*, *-WFD-*, WFDPRINT-*); COM has no ids and
# localises the names, so they are matched by group and profiles. One CIM
# query, because Get-NetFirewallRule with its filters takes seconds.
function Get-WfdKeys {
  $q = "Direction = 1 AND (InstanceID LIKE '%WFD%' OR InstanceID LIKE 'WiFiDirect%')"
  foreach ($w in @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetFirewallRule -Filter $q -ErrorAction SilentlyContinue)) {
    $prof = [int]$w.Profiles; if (-not $prof) { $prof = 0x7FFFFFFF }   # 0 is "any" here, all bits in COM
    "$($w.RuleGroup)|$prof"
  }
}

function Get-FwState {
  try {
    $fw = New-Object -ComObject HNetCfg.FwPolicy2
    $cur = [int]$fw.CurrentProfileTypes
    $active = @(1, 2, 4 | Where-Object { $cur -band $_ })
    $wfd = @(Get-WfdKeys)
    $rules = foreach ($r in @($fw.Rules)) {
      if (-not $r.Enabled -or $r.Direction -ne 1 -or -not ($r.Profiles -band $cur)) { continue }
      # Rules of Store and other packaged apps (Game Bar, Teams, Store itself)
      # carry an owner or a package and allow everything, but only inside that
      # app's container. Counted as global, they would open every port.
      if ($r.LocalUserOwner -or $r.LocalAppPackageId) { continue }
      if ($wfd -contains "$($r.Grouping)|$($r.Profiles)") { continue }
      [pscustomobject]@{
        Allow = ($r.Action -eq 1); Proto = [int]$r.Protocol; Ports = [string]$r.LocalPorts
        App = [Environment]::ExpandEnvironmentVariables([string]$r.ApplicationName)
        Svc = [string]$r.ServiceName; Remote = [string]$r.RemoteAddresses
      }
    }
    [pscustomobject]@{
      Profiles = $active
      Enabled = -not @($active | Where-Object { -not $fw.FirewallEnabled($_) }).Count
      Off = @(1, 2, 4 | Where-Object { -not $fw.FirewallEnabled($_) })
      BlockAll = $active.Count -and -not @($active | Where-Object { -not $fw.BlockAllInboundTraffic($_) }).Count
      DefaultBlock = -not @($active | Where-Object { $fw.DefaultInboundAction($_) -ne 0 }).Count
      Rules = @($rules)
    }
  } catch { $null }
}

function Test-PortSpec([string]$spec, [int]$port, [bool]$rpc) {
  if (-not $spec -or $spec -eq '*') { return $true }
  foreach ($p in $spec.Split(',')) {
    $p = $p.Trim()
    if ($p -match '^\d+$') { if ([int]$p -eq $port) { return $true } }
    elseif ($p -match '^(\d+)-(\d+)$') { if ($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) { return $true } }
    # keywords: dynamic RPC endpoints of RPC services, and the endpoint mapper
    elseif ($p -eq 'RPC') { if ($rpc -and $port -ge 49152) { return $true } }
    elseif ($p -eq 'RPC-EPMap') { if ($port -eq 135) { return $true } }
  }
  $false
}

function Test-RuleHit($r, [int]$port, $proc) {
  if ($r.Proto -ne 6 -and $r.Proto -ne 256) { return $false }
  if (-not (Test-PortSpec $r.Ports $port ($proc.Services.Count -gt 0))) { return $false }
  if ($r.App -and $r.App -ne '*') {
    # An unknown path (another user's process, no admin rights) cannot be
    # ruled out, so the rule counts: this check has to err towards "reachable".
    if ($proc.Path -and $r.App -ne $proc.Path) { return $false }
  }
  if ($r.Svc -and $r.Svc -ne '*' -and -not ($proc.Services -contains $r.Svc)) { return $false }
  $true
}

function Get-Reach($fw, [int]$port, $proc) {  # open | lan | blocked
  if (-not $fw -or -not $fw.Enabled) { return 'open' }
  if ($fw.BlockAll) { return 'blocked' }
  $hits = @($fw.Rules | Where-Object { Test-RuleHit $_ $port $proc })
  # a matching block rule beats an allow rule
  if (@($hits | Where-Object { -not $_.Allow }).Count) { return 'blocked' }
  $allow = @($hits | Where-Object { $_.Allow })
  if (-not $allow.Count) { if ($fw.DefaultBlock) { return 'blocked' } else { return 'open' } }
  if (@($allow | Where-Object { $_.Remote -notmatch '^LocalSubnet[46]?$' }).Count) { return 'open' }
  'lan'
}

# Windows' own processes open dynamic RPC endpoints (49152 and up) on every
# machine, and which services own them varies from one machine to the next. While
# the firewall drops them they are part of the OS, not a finding, allowlisted or
# not; one row says so. A reachable one is judged like any other listener.
$SYS_RPC = 'lsass', 'wininit', 'services', 'spoolsv', 'svchost'

# Windows' built-in VPN (IKEv2, SSTP, L2TP, PPTP) has no adapter with a telling
# name: its link is a PPP interface named after the connection. PPPoE broadband
# is PPP as well, so a PPP link is a tunnel only when Windows itself lists it as
# a connected VPN connection. Nothing here is inferred from a name that merely
# sounds like a VPN: a wrong "inside the tunnel" is the one answer this check
# must never give.
function Test-Tunnel([string]$text, [string]$alias, [string]$type, [string[]]$vpnUp) {
  if ($text -match $TUNNEL_MATCH) { return $true }
  [bool]($type -eq 'Ppp' -and $alias -and $vpnUp -contains $alias)
}

function Test-SystemRpc([int]$port, [string]$name, [string]$reach) {
  $port -ge 49152 -and $name -in $SYS_RPC -and $reach -eq 'blocked'
}

function Test-Allowed($proc) {
  if ($ALLOWED_LISTENERS -contains $proc.Name) { return $true }
  foreach ($s in $proc.Services) { if ($ALLOWED_LISTENERS -contains "$($proc.Name):$s") { return $true } }
  $false
}

function Get-PortEntry([int]$port, $proc) {  # @{Name; Risk; Fix; Class} or $null
  if ($proc.Cmd -match 'http\.server') { $key = 'http.server'; $cls = 'dev' }
  else {
    $meta = $PORT_META[$port]; if (-not $meta) { return $null }
    $cls, $who = $meta.Split('|', 2)
    if ($proc.Name -notmatch $who) { return $null }
    $key = $port
  }
  $name, $risk, $fix = $PORT_TEXT[$key].Split('|')
  [pscustomobject]@{ Name = $name; Risk = $risk; Fix = $fix; Class = $cls }
}

function Get-PortVerdict([string]$reach, [bool]$allowed, [bool]$risky) {  # status, message id
  switch ($reach) {
    'blocked' { if ($allowed) { 'ok', 'p_ok_blk' } else { 'warn', 'p_unl_blk' } }
    'lan'     { if (-not $allowed) { 'bad', 'p_bad_lan' } elseif ($risky) { 'warn', 'p_risky_lan' } else { 'ok', 'p_ok_open' } }
    default   { if (-not $allowed) { 'bad', 'p_bad' } elseif ($risky) { 'warn', 'p_risky' } else { 'ok', 'p_ok_open' } }
  }
}

# A command line can carry a token as an argument, and this one ends up in the
# terminal and the log. Anything that looks like a secret is cut out.
function Clean-Cmd([string]$c) {
  $c = Clean ($c -replace '\s+', ' ')
  $c = $c -replace '(?i)((?:token|key|secret|passw(?:or)?d|pwd|auth)[\w-]*(?:=|:|\s+))\S+', '$1…'
  $c = $c -replace '[A-Za-z0-9_\-+/=]{32,}', '…'
  if ($c.Length -gt 80) { $c = $c.Substring(0, 79) + '…' }
  $c
}

function Format-Age([datetime]$since) {
  $d = (Get-Date) - $since
  if ($d.TotalDays -ge 1) { Fmt age_d ([int][Math]::Floor($d.TotalDays)) }
  elseif ($d.TotalHours -ge 1) { Fmt age_h ([int][Math]::Floor($d.TotalHours)) }
  else { Fmt age_m ([int][Math]::Max(1, [Math]::Floor($d.TotalMinutes))) }
}

# --- AI agent helpers ---
# Token formats that are unambiguous on their own. A reference such as
# ${GITHUB_TOKEN} is not a token and does not match.
$TOKEN_KINDS = [ordered]@{
  Anthropic = 'sk-ant-[A-Za-z0-9_\-]{20,}'
  OpenAI    = 'sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}'
  GitHub    = 'gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}'
  GitLab    = 'glpat-[A-Za-z0-9_\-]{20,}'
  Slack     = 'xox[abposr]-[A-Za-z0-9\-]{10,}'
  AWS       = 'AKIA[0-9A-Z]{16}'
  Google    = 'AIza[0-9A-Za-z_\-]{35}'
  Stripe    = '[rs]k_live_[A-Za-z0-9]{20,}'
  Bearer    = 'Bearer\s+[A-Za-z0-9._~+/\-]{20,}'
}
function Find-Tokens([string]$text) {  # the kinds of token found, never the token
  foreach ($k in $TOKEN_KINDS.Keys) { if ($text -match $TOKEN_KINDS[$k]) { $k } }
}

# npx -y some-server runs whatever version is newest at that moment: a
# hijacked release reaches the machine on the next start with no review.
function Test-Unpinned($cmd, $argv) {
  $c = [IO.Path]::GetFileNameWithoutExtension([string]$cmd)
  $a = @($argv | ForEach-Object { [string]$_ })
  if ($c -in 'pnpm', 'yarn' -and $a.Count -and $a[0] -eq 'dlx') { $a = @($a | Select-Object -Skip 1) }
  elseif ($c -notin 'npx', 'bunx', 'uvx', 'pnpx') { return $false }
  $pkg = $a | Where-Object { $_ -notmatch '^-' } | Select-Object -First 1
  if (-not $pkg) { return $false }
  if ($c -eq 'uvx') { return $pkg -notmatch '==|@\d' }
  # pkg@latest is no more pinned than pkg; only a version number pins it
  ($pkg -replace '^@[^/]+/', '') -notmatch '@[v~^]?\d'
}

function Get-McpServers {  # file, server name, its config as text, command, args
  $json = @(
    @{ File = "$HOME_DIR\.claude.json"; Short = '.claude.json' }
    @{ File = "$APPDATA_DIR\Claude\claude_desktop_config.json"; Short = 'claude_desktop_config.json' }
    @{ File = "$HOME_DIR\.cursor\mcp.json"; Short = '.cursor\mcp.json' }
  )
  foreach ($j in $json) {
    if (-not (Test-Path -LiteralPath $j.File)) { continue }
    try { $o = Get-Content -LiteralPath $j.File -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
    $sets = @($o.mcpServers)
    foreach ($p in @($o.projects.PSObject.Properties)) { if ($p) { $sets += $p.Value.mcpServers } }
    foreach ($set in $sets) {
      foreach ($s in @($set.PSObject.Properties)) {
        if (-not $s) { continue }
        [pscustomobject]@{ File = $j.Short; Name = $s.Name; Text = ($s.Value | ConvertTo-Json -Depth 8 -Compress)
          Cmd = $s.Value.command; Args = $s.Value.args }
      }
    }
  }
  $toml = "$HOME_DIR\.codex\config.toml"
  if (Test-Path -LiteralPath $toml) {
    $cur = $null; $buf = @{}
    foreach ($line in Get-Content -LiteralPath $toml -Encoding UTF8) {
      if ($line -match '^\s*\[mcp_servers\.([^.\]]+)') { $cur = $Matches[1].Trim('"'''); if (-not $buf[$cur]) { $buf[$cur] = @() } }
      elseif ($line -match '^\s*\[') { $cur = $null }
      if ($cur) { $buf[$cur] += $line }
    }
    foreach ($n in $buf.Keys) {
      $text = $buf[$n] -join "`n"
      $cmd = if ($text -match '(?m)^\s*command\s*=\s*"([^"]*)"') { $Matches[1] }
      $argv = if ($text -match '(?m)^\s*args\s*=\s*\[(.*)\]') { [regex]::Matches($Matches[1], '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value } }
      [pscustomobject]@{ File = '.codex\config.toml'; Name = $n; Text = $text; Cmd = $cmd; Args = $argv }
    }
  }
}

function Toml-Top([string]$file, [string]$key) {  # a top-level string value, before any [section]
  foreach ($line in Get-Content -LiteralPath $file -Encoding UTF8) {
    if ($line -match '^\s*\[') { break }
    if ($line -match "^\s*$key\s*=\s*[`"']([^`"']*)[`"']") { return $Matches[1] }
  }
  $null
}

# The tests dot-source the script with this set to reach the functions above
# without running a check.
if ($env:SECCHECK_LIB) { return }

# --- flags ---
$QUIET = $false; $JSON = $false; $NO_NET = $false; $NOTIFY = $false; $LOGGING = $false
for ($i = 0; $i -lt $args.Count; $i++) {
  switch -CaseSensitive ($args[$i]) {
    { $_ -in '--quiet', '-q' } { $QUIET = $true; break }
    '--json'            { $JSON = $true; break }
    '--no-net'          { $NO_NET = $true; break }
    '--notify'          { $NOTIFY = $true; break }
    '--log'             { $LOGGING = $true; break }   # used by the scheduled task
    '--install-agent'   { exit (Install-Agent $args[$i + 1]) }
    '--uninstall-agent' { exit (Uninstall-Agent) }
    '--init-config'     { exit (Init-Config) }
    { $_ -in '--version', '-V' } { [Console]::Out.WriteLine("seccheck $VERSION"); exit 0 }
    { $_ -in '--help', '-h' } { [Console]::Out.WriteLine((Fmt usage $CONF)); exit 0 }
    default {
      [Console]::Error.WriteLine("seccheck: $(Fmt bad_opt $args[$i])")
      [Console]::Error.WriteLine((Fmt usage $CONF)); exit 64
    }
  }
}

# --- output ---
$COLOR = -not $JSON -and -not $LOGGING -and -not [Console]::IsOutputRedirected
$LOGBUF = New-Object Collections.Generic.List[string]

$WARNS = 0; $FAILS = 0
$JROWS = New-Object Collections.Generic.List[object]
$ISSUES = New-Object Collections.Generic.List[string]
$ISSUE_NAME = @{}; $ISSUE_TEXT = @{}

$NAME_W = 20

function Emit([string]$line, [string]$color) {
  if ($LOGGING) { $LOGBUF.Add($line) }
  elseif ($COLOR -and $color) { Write-Host $line -ForegroundColor $color }
  else { [Console]::Out.WriteLine($line) }
}

# A problem's identity between runs is its stable key, never its text. The
# text is localised and may carry volatile parts (the exit address, the disk
# percentage); if it were the identity, every new digit would look like a new
# problem and fire a new notification.
function Row([string]$st, [string]$name, [string]$val, [string]$key, [string[]]$details) {
  if (-not $key -or $key -eq '-') { $key = $name }
  $id = "$st|$key"
  switch ($st) {
    'ok'   { $mark = '✓'; $col = 'Green' }
    'warn' { $mark = '!'; $col = 'Yellow'; $script:WARNS++ }
    'bad'  { $mark = '✗'; $col = 'Red'; $script:FAILS++ }
  }
  $j = [ordered]@{ status = $st; check = $name; value = $val }
  if ($details) { $j.details = @($details) }
  $JROWS.Add($j)
  if ($st -ne 'ok') { $ISSUES.Add($id); $ISSUE_NAME[$id] = $name; $ISSUE_TEXT[$id] = $val }
  if ($JSON) { return }
  if ($QUIET -and $st -eq 'ok') { return }
  $sp = ' ' * [Math]::Max(1, $NAME_W - $name.Length)
  if ($COLOR) {
    Write-Host '  ' -NoNewline; Write-Host $mark -ForegroundColor $col -NoNewline; Write-Host "  $name$sp$val"
  } else { Emit "  $mark  $name$sp$val" }
  foreach ($d in $details) { Emit ((' ' * ($NAME_W + 5)) + $d) 'DarkGray' }
}

function Chk([string]$st, [string]$name, [string]$key, [string]$msg) {  # Chk <status> <label> <stable key> <message id> [args…]
  Row $st $name (Fmt $msg @args) $key
}

function Head([string]$id) { if ($JSON -or $QUIET) { return }; Emit ''; Emit "  $($T[$id])" 'White' }

# ───────────────────────────── network ─────────────────────────────
Head h_net

# The route Windows would actually use for an internet address. Asking for
# one address rather than for 0.0.0.0/0 also catches VPNs that install two
# half routes (0.0.0.0/1 and 128.0.0.0/1) instead of replacing the default.
function Route-For([string]$ip) {
  try { $r = @(Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop); $r[-1] } catch { $null }
}
function Get-IfType([int]$ifIndex) {  # Ppp, Ethernet, Wireless80211…; .NET sees PPP links, Get-NetAdapter does not
  foreach ($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    $p = $n.GetIPProperties()
    foreach ($get in 'GetIPv4Properties', 'GetIPv6Properties') {
      try { if ($p.$get().Index -eq $ifIndex) { return [string]$n.NetworkInterfaceType } } catch {}
    }
  }
  ''
}
$VPN_UP = $null   # connected built-in VPN connections, asked for only when a PPP link carries traffic
function Is-Tunnel([int]$ifIndex) {
  $a = Get-NetAdapter -InterfaceIndex $ifIndex -IncludeHidden -ErrorAction SilentlyContinue
  $alias = [string](Get-NetIPInterface -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceAlias
  $text = if ($a) { "$($a.Name) $($a.InterfaceDescription)" } else { $alias }
  if ($text -match $TUNNEL_MATCH) { return $true }
  $type = Get-IfType $ifIndex
  if ($type -eq 'Ppp' -and $null -eq $script:VPN_UP) {
    $script:VPN_UP = @(@(Get-VpnConnection -ErrorAction SilentlyContinue) + @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) |
      Where-Object { $_ -and $_.ConnectionStatus -eq 'Connected' } | ForEach-Object { [string]$_.Name })
  }
  Test-Tunnel $text $alias $type $script:VPN_UP
}

$R4 = Route-For '1.1.1.1'
$ROUTE_TUN = $false
if (-not $R4) {
  Chk bad $T.l_route route:none route_none
} else {
  $ROUTE_TUN = Is-Tunnel $R4.InterfaceIndex
  if ($ROUTE_TUN) { Chk ok $T.l_route - route_tun $R4.InterfaceAlias }
  elseif ($VPN_EXPECTED) {
    # A virtual adapter seccheck does not know stays an alarm: it may be the
    # VPN, but a name is not proof. The row says how to teach it the adapter.
    $hint = @()
    if (-not (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $R4.InterfaceIndex })) {
      $hint = @(Fmt d_tunnel_hint $R4.InterfaceAlias)
    }
    Row bad $T.l_route (Fmt route_out $R4.InterfaceAlias) route:bypass $hint
  }
  else { Chk ok $T.l_route - route_plain $R4.InterfaceAlias }
}

# physical uplink: an adapter that is up, has an address and is not a tunnel
$PHYS = $null; $PHYS_IP = $null
$ups = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Sort-Object InterfaceMetric, ifIndex)
foreach ($a in $ups) {
  if ("$($a.Name) $($a.InterfaceDescription)" -match $TUNNEL_MATCH) { continue }
  $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1
  if ($ip) { $PHYS = $a; $PHYS_IP = $ip.IPAddress; break }
}
if ($PHYS) { Chk ok $T.l_uplink - uplink_ok $PHYS.Name $PHYS_IP }
else { Chk warn $T.l_uplink uplink:none uplink_none }

# The network profile decides which firewall rules apply: on Public, sharing
# and discovery are closed; on Private, other machines on the network see this one.
if ($PHYS) {
  $prof = Get-NetConnectionProfile -InterfaceIndex $PHYS.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($prof) {
    switch ([string]$prof.NetworkCategory) {
      'Public'  { Chk ok $T.l_profile - prof_public $PHYS.Name }
      'Private' { if ($VPN_EXPECTED) { Chk warn $T.l_profile profile:private prof_private $PHYS.Name } else { Chk ok $T.l_profile - prof_private $PHYS.Name } }
      default   { Chk ok $T.l_profile - prof_domain $PHYS.Name }
    }
  }
}

# DNS: the resolvers of the interface that carries the route. Windows may still
# send a query out of every interface that has a resolver (smart multi-homed
# name resolution), so a tunnel resolver is necessary, not sufficient.
$DNS_IF = $null; $DNS_NS = $null
if ($R4) {
  $cands = @($R4.InterfaceIndex) + @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected -ErrorAction SilentlyContinue |
    Sort-Object InterfaceMetric | ForEach-Object ifIndex)
  foreach ($ix in $cands) {
    $ns = @((Get-DnsClientServerAddress -InterfaceIndex $ix -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
    if ($ns.Count -and $ns[0]) { $DNS_IF = $ix; $DNS_NS = $ns[0]; break }
  }
}
if (-not $DNS_NS) {
  Chk warn $T.l_dns dns:none dns_none
} else {
  $dnsAlias = (Get-NetIPInterface -InterfaceIndex $DNS_IF -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceAlias
  if ((Is-Tunnel $DNS_IF) -or -not $VPN_EXPECTED) { Chk ok $T.l_dns - dns_via $DNS_NS (Or $dnsAlias $T.unknown) }
  else { Chk bad $T.l_dns dns:bypass dns_out $DNS_NS (Or $dnsAlias $T.unknown) }
}

# IPv6: either inside the tunnel or no route at all
$R6 = Route-For '2606:4700:4700::1111'
if (-not $R6) { Chk ok $T.l_ipv6 - v6_none }
elseif (Is-Tunnel $R6.InterfaceIndex) { Chk ok $T.l_ipv6 - v6_tun $R6.InterfaceAlias }
elseif ($VPN_EXPECTED) { Chk bad $T.l_ipv6 ipv6:bypass v6_out $R6.InterfaceAlias }
else { Chk ok $T.l_ipv6 - v6_plain $R6.InterfaceAlias }

# exit point
if ($NO_NET) {
  Chk ok $T.l_exit - exit_skip
} else {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $E = $null
  foreach ($u in $IP_ENDPOINTS) {
    $body = Fetch $u
    if ($body) { try { $E = $body | ConvertFrom-Json; break } catch { $E = $null } }
  }
  # These strings come from a remote service and end up in the terminal, in a
  # notification and, for the address, in a URL. Control characters are
  # dropped, and anything that is not an address literal is not an answer.
  $E_IP = Clean $E.ip; $E_CITY = Clean $E.city; $E_CC = Clean $E.country
  $E_ORG = Clean (Or $E.org $E.asn_org)
  if (-not (Is-Ip $E_IP)) {
    Chk warn $T.l_exit exit:noresp exit_noresp
  } elseif (-not $VPN_EXPECTED) {
    Chk ok $T.l_exit - exit_ok $E_CITY $E_CC $E_ORG
  } elseif (-not $VPN_ORG_MATCH) {
    Chk warn $T.l_exit exit:unset exit_unset $E_CITY $E_CC $E_ORG
  } elseif (Vpn-Match $E_ORG) {
    Chk ok $T.l_exit - exit_ok $E_CITY $E_CC $E_ORG
  } else {
    # The ASN name is whoever ANNOUNCES the route, not whoever owns the address
    # block. VPN providers often announce their own blocks through a hosting
    # company, so before raising the alarm, ask the registry who the block
    # belongs to.
    $E_OWNER = $null
    if ($RDAP_ENDPOINT) {
      $rd = Fetch "$RDAP_ENDPOINT/$E_IP" -HttpsOnly
      if ($rd) {
        try { $ro = $rd | ConvertFrom-Json } catch { $ro = $null }
        if ($ro) { foreach ($cand in Rdap-Owners $ro) { $E_OWNER = Vpn-Match $cand; if ($E_OWNER) { break } } }
      }
    }
    if ($E_OWNER) { Chk ok $T.l_exit - exit_owner $E_CITY $E_CC $E_ORG $E_OWNER }
    # keyed by the ASN, not the address: the address changes on every reconnect
    else { Chk bad $T.l_exit "exit:$E_ORG" exit_bad $E_IP $E_CITY $E_CC $E_ORG }
  }
}

# is the local gateway reachable
$GW = $null
if ($PHYS) {
  $GW = (Get-NetRoute -InterfaceIndex $PHYS.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric | Select-Object -First 1).NextHop
}
if (-not $GW -or $GW -eq '0.0.0.0') {
  Chk ok $T.l_gw - gw_none
} else {
  $st = $null
  try { $st = [string](New-Object Net.NetworkInformation.Ping).Send($GW, 1200).Status } catch { $st = 'Error' }
  if ($st -eq 'Success') {
    if ($VPN_EXPECTED) { Chk warn $T.l_gw "gw:$GW" gw_up $GW } else { Chk ok $T.l_gw - gw_up_plain $GW }
  } elseif ($st -eq 'TimedOut' -or $st -like 'Destination*Unreachable') {
    Chk ok $T.l_gw - gw_down $GW
  } else {
    # The packet never left: something local refused to send it, a VPN kill
    # switch or a firewall rule. That says nothing about other processes, so
    # the row does not claim the LAN is cut off.
    Chk ok $T.l_gw - gw_blocked $GW
  }
}

# ─────────────────── ports open to the network ───────────────────
Head h_ports

$LISTEN = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$|fe80:)' } |
  Sort-Object LocalPort -Unique)

if (-not $LISTEN.Count) {
  Chk ok $T.l_listen - listen_none
} else {
  $FW = Get-FwState
  # one query for all services, instead of one per svchost
  $SVC = @{}
  foreach ($s in @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue)) {
    $SVC[[int]$s.ProcessId] = @($SVC[[int]$s.ProcessId] | Where-Object { $_ }) + $s.Name
  }
  $RPC = New-Object Collections.Generic.List[int]
  foreach ($c in $LISTEN) {
    $port = [int]$c.LocalPort; $procId = [int]$c.OwningProcess
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    $name = if ($procId -eq 4) { 'System' } elseif ($p) { $p.ProcessName } else { '' }
    $path = $null; $start = $null
    if ($p) { try { $path = $p.Path } catch {}; try { $start = $p.StartTime } catch {} }
    if ($name -eq 'svchost' -and -not $path) { $path = "$env:windir\System32\svchost.exe" }
    if ($name -eq 'System') { $path = 'System' }
    $svcs = @($SVC[$procId] | Where-Object { $_ })
    $proc = [pscustomobject]@{ Name = $name; Path = $path; Services = $svcs; Cmd = $null }

    $label = "$port/tcp"
    if (-not $name) { Row warn $label (Fmt p_unk) "port:${port}:unknown"; continue }
    $reach = Get-Reach $FW $port $proc
    if (Test-SystemRpc $port $name $reach) { $RPC.Add($port); continue }

    # the command line of the user's own processes is readable without admin
    # rights; it tells a Python http.server from any other Python
    if ($name -notin $SYS_RPC -and $name -ne 'System') {
      try { $proc.Cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction Stop).CommandLine } catch {}
    }
    $entry = Get-PortEntry $port $proc
    $who = if ($name -eq 'svchost' -and $svcs.Count) { "svchost: $($svcs[0])" } else { $name }
    $what = if ($entry) { "$($entry.Name) ($who)" } else { $who }
    $risky = [bool]($entry -and $entry.Class -in 'exec', 'data', 'ai')
    $st, $msg = Get-PortVerdict $reach (Test-Allowed $proc) $risky

    $details = @()
    if ($st -ne 'ok') {
      $details += if ($start) { Fmt d_pid_age $procId (Format-Age $start) } else { Fmt d_pid $procId }
      if ($proc.Cmd) { $details += Fmt d_cmd (Clean-Cmd $proc.Cmd) }
      if ($entry -and $entry.Risk) { $details += Fmt d_risk $entry.Risk }
      if ($entry -and $entry.Fix) { $details += Fmt d_fix $entry.Fix }
    }
    Row $st $label (Fmt $msg $what) "port:${port}:$name" $details
  }
  if ($RPC.Count) {
    $lo = ($RPC | Measure-Object -Minimum).Minimum; $hi = ($RPC | Measure-Object -Maximum).Maximum
    $label = if ($lo -eq $hi) { "$lo/tcp" } else { "$lo–$hi" }
    Chk ok $label - p_rpc $RPC.Count
  }
}

# ───────────────────────────── device ─────────────────────────────
Head h_dev

# BitLocker without admin rights: manage-bde and Get-BitLockerVolume both need
# elevation, but Explorer's volume property is readable by anyone.
$SYSDRV = $env:SystemDrive
$BL = $null
try { $BL = (New-Object -ComObject Shell.Application).NameSpace("$SYSDRV\").Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch {}
switch ([string]$BL) {
  { $_ -in '1', '6' } { Chk ok $T.l_bl - bl_on $SYSDRV }
  '3'     { Chk warn $T.l_bl bitlocker:encrypting bl_enc $SYSDRV }
  '4'     { Chk bad $T.l_bl bitlocker:decrypting bl_dec $SYSDRV }
  '5'     { Chk bad $T.l_bl bitlocker:suspended bl_susp $SYSDRV }
  '8'     { Chk bad $T.l_bl bitlocker:waiting bl_wait $SYSDRV }
  '2'     { Chk bad $T.l_bl bitlocker:off bl_off $SYSDRV }
  default { Chk warn $T.l_bl bitlocker:unknown bl_unk }
}

# Defender, or whatever antivirus Windows Security Center says is active
$MP = $null
try { $MP = Get-MpComputerStatus -ErrorAction Stop } catch {}
if ($MP -and $MP.RealTimeProtectionEnabled) {
  if ($MP.AntivirusSignatureAge -gt 7) { Chk warn $T.l_av av:old av_old $MP.AntivirusSignatureAge }
  else { Chk ok $T.l_av - av_on }
} else {
  $other = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
    Where-Object { (($_.productState -shr 12) -band 0xF) -eq 1 -and $_.displayName -notmatch 'Defender' })
  if ($other.Count) { Chk ok $T.l_av - av_other (Clean $other[0].displayName) }
  else { Chk bad $T.l_av antivirus off_loud }
}

$FW = if ($FW) { $FW } else { Get-FwState }
if (-not $FW) {
  Chk warn $T.l_fw firewall:unknown fw_unk
} elseif (-not $FW.Off.Count) {
  Chk ok $T.l_fw - fw_on
} else {
  $offNames = ($FW.Off | ForEach-Object { $T["fwp_$_"] }) -join ', '
  if (@($FW.Off | Where-Object { $FW.Profiles -contains $_ }).Count) {
    Chk bad $T.l_fw firewall:current fw_cur $offNames
  } else { Chk warn $T.l_fw "firewall:$($FW.Off -join ',')" fw_part $offNames }
}

$SB = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue).UEFISecureBootEnabled
if ($SB -eq 1) { Chk ok $T.l_sb - on }
elseif ($null -ne $SB) { Chk bad $T.l_sb secureboot off_loud }
else { Chk warn $T.l_sb secureboot:unknown sb_unk }

$UAC = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
if ($UAC.EnableLUA -eq 0) { Chk bad $T.l_uac uac off_loud }
elseif ($UAC.ConsentPromptBehaviorAdmin -eq 0) { Chk bad $T.l_uac uac:silent uac_silent }
else { Chk ok $T.l_uac - on }

# SMBv1: the client driver is a service of its own once the feature is
# installed; the server side is a registry switch.
$SMB1C = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -ErrorAction SilentlyContinue
$SMB1S = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue).SMB1
if (($SMB1C -and $SMB1C.Start -ne 4) -or $SMB1S -eq 1) { Chk bad $T.l_smb1 smb1 smb1_on }
else { Chk ok $T.l_smb1 - off }

$RDP = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
if ($RDP -eq 0) { Chk warn $T.l_rdp rdp rdp_on }
else { Chk ok $T.l_rdp - off }

# Windows updates, not Defender definitions: those arrive daily and would
# make the row always look fresh. Get-HotFix lists only OS updates.
$HF = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
if ($HF.Count) {
  $days = [int]((Get-Date) - $HF[0].InstalledOn).TotalDays
  if ($days -gt 60) { Chk bad $T.l_upd updates:old upd_ok $days }
  elseif ($days -gt 40) { Chk warn $T.l_upd updates:late upd_ok $days }
  else { Chk ok $T.l_upd - upd_ok $days }
} else { Chk warn $T.l_upd updates:unknown upd_unk }

$DRV = Get-PSDrive -Name $SYSDRV.TrimEnd(':') -ErrorAction SilentlyContinue
if ($DRV -and ($DRV.Used + $DRV.Free) -gt 0) {
  $USEPCT = [int][Math]::Round(100 * $DRV.Used / ($DRV.Used + $DRV.Free)); $FREE = [int][Math]::Floor($DRV.Free / 1GB)
  if ($USEPCT -ge 95) { Chk bad $T.l_disk disk disk_bad $USEPCT $FREE }
  elseif ($USEPCT -ge 85) { Chk warn $T.l_disk disk disk $USEPCT $FREE }
  else { Chk ok $T.l_disk - disk $USEPCT $FREE }
}

# ─────────────────────────── AI agents ───────────────────────────
# An agent runs as you, with your keys, and takes instructions from whatever
# it reads. These rows show how much it may do without asking, and they
# change the moment a setting is loosened, which is what the notification is for.
$CC_DIR = "$HOME_DIR\.claude"
$CX_TOML = "$HOME_DIR\.codex\config.toml"
$OLLAMA = (Test-Path "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe") -or [bool](Get-Command ollama -ErrorAction SilentlyContinue)
$MCP = @(Get-McpServers)

if ((Test-Path -LiteralPath $CC_DIR) -or (Test-Path -LiteralPath $CX_TOML) -or $OLLAMA -or $MCP.Count) { Head h_ai }

if (Test-Path -LiteralPath $CC_DIR) {
  $CS = $null; $bad = $null
  $sf = "$CC_DIR\settings.json"
  if (Test-Path -LiteralPath $sf) {
    try { $CS = Get-Content -LiteralPath $sf -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop } catch { $bad = Clean $_.Exception.Message }
  }
  if ($bad) {
    Chk warn $T.l_cc cc:unreadable cc_bad_json ($bad.Split("`n")[0])
  } else {
    if ($CS.permissions.defaultMode -eq 'bypassPermissions') { Chk bad $T.l_cc cc:bypass-default cc_default }
    elseif ($CS.permissions.disableBypassPermissionsMode -eq 'disable') { Chk ok $T.l_cc - cc_off }
    else { Chk warn $T.l_cc cc:bypass cc_on }
    $deny = @($CS.permissions.deny | Where-Object { $_ })
    if ($deny.Count) { Chk ok $T.l_ccdeny - cc_deny $deny.Count }
    else { Chk warn $T.l_ccdeny cc:deny cc_deny_none }
  }
}

if (Test-Path -LiteralPath $CX_TOML) {
  $sbx = Toml-Top $CX_TOML 'sandbox_mode'; $apr = Toml-Top $CX_TOML 'approval_policy'
  if ($sbx -eq 'danger-full-access') { Chk bad $T.l_codex codex:full cx_full }
  elseif ($apr -eq 'never') { Chk warn $T.l_codex codex:never cx_never }
  else { Chk ok $T.l_codex - cx_ok (Or $sbx $T.cx_default) (Or $apr $T.cx_default) }
}

if ($MCP.Count) {
  $found = 0
  foreach ($m in $MCP) {
    $label = "MCP: $(Clean $m.Name)"
    if ($label.Length -ge $NAME_W) { $label = $label.Substring(0, $NAME_W - 2) + '…' }
    foreach ($kind in Find-Tokens $m.Text) {
      $found++; Chk bad $label "mcp:$($m.File):$($m.Name):$kind" mcp_token $kind $m.File
    }
    if (Test-Unpinned $m.Cmd $m.Args) {
      $found++; Chk warn $label "mcp:$($m.File):$($m.Name):unpinned" mcp_unpinned (Clean (@($m.Args | Where-Object { $_ -notmatch '^-' })[0]))
    }
  }
  if (-not $found) { Chk ok $T.l_mcp - mcp_ok $MCP.Count }
}

if ($OLLAMA) {
  # the registry too: a value set with setx reaches Ollama on its next start,
  # but not this process, which inherited the environment from before
  $OH = Or (Or $env:OLLAMA_HOST ([Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'User'))) ([Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'Machine'))
  if (-not $OH -or $OH -match '^(https?://)?(127\.0\.0\.1|localhost|\[::1\])(:\d+)?/?$') { Chk ok $T.l_ollama - ol_ok }
  else { Chk bad $T.l_ollama ollama:host ol_open (Clean $OH) }
}

# ───────────────────────────── summary ─────────────────────────────
if ($JSON) {
  $doc = [ordered]@{ version = $VERSION; platform = 'windows'; ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    warnings = $WARNS; failures = $FAILS; rows = $JROWS.ToArray() }
  [Console]::Out.WriteLine(($doc | ConvertTo-Json -Depth 5 -Compress))
} elseif (-not $QUIET -or $WARNS -or $FAILS) {
  Emit ''
  if ($FAILS) { Emit "  $(Fmt sum_bad $FAILS)$(Fmt sum_bad_w $WARNS)" 'Red' }
  elseif ($WARNS) { Emit "  $(Fmt sum_warn $WARNS)$($T.sum_warn_b)" 'Yellow' }
  else { Emit "  $($T.sum_ok)" 'Green' }
  Emit "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" 'DarkGray'
  Emit ''
}

# Notify on a CHANGE of state, not on the state itself. A monitor that repeats
# the same thing every half hour turns into noise within two days, and the one
# genuinely new line gets lost along with the old reminder.
function Notify([string]$title, [string]$body) {
  $title = "seccheck: $title"
  # the tests point this at a file instead of the screen
  if ($env:SECCHECK_NOTIFY_LOG) { [IO.File]::AppendAllText($env:SECCHECK_NOTIFY_LOG, "$title | $body`n"); return }
  try {
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    $x = New-Object Windows.Data.Xml.Dom.XmlDocument
    $e = [Security.SecurityElement]
    $x.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$($e::Escape($title))</text><text>$($e::Escape($body))</text></binding></visual></toast>")
    # shown as Windows PowerShell: an unregistered app id is silently dropped
    $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show((New-Object Windows.UI.Notifications.ToastNotification $x))
  } catch {}
}

if ($NOTIFY) {
  $sorted = [string[]]$ISSUES.ToArray(); [Array]::Sort($sorted, [StringComparer]::Ordinal)
  $now = $sorted -join "`n"
  $prev = if (Test-Path -LiteralPath $STATE_FILE) { ([IO.File]::ReadAllText($STATE_FILE)).TrimEnd("`r", "`n") } else { '' }

  if ($now -ne $prev) {
    $old = @($prev -split "`n")
    $fresh = @($sorted | Where-Object { $old -notcontains $_ })
    if ($fresh.Count) {
      $f = $fresh[0]; $more = if ($fresh.Count -gt 1) { " (+$($fresh.Count - 1))" } else { '' }
      Notify "$($ISSUE_NAME[$f])$more" $ISSUE_TEXT[$f]
    } elseif (-not $now) {
      Notify $T.n_clean $T.n_clean_body
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $STATE_FILE) | Out-Null
    [IO.File]::WriteAllText($STATE_FILE, $now, (New-Object Text.UTF8Encoding $false))
  }
}

if ($LOGGING -and $LOGBUF.Count) {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LOG) | Out-Null
  [IO.File]::AppendAllText($LOG, (($LOGBUF -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding $false))
}

if ($FAILS) { exit 2 }
if ($WARNS) { exit 1 }
exit 0

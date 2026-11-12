#!/bin/zsh
# Offline tests for seccheck.
#
# The exit address and the registry record are read from local files, osascript
# is replaced by a stub that only records what it was asked to show, and the
# config and state live in a temp directory. No real notification is sent and
# nothing in the home directory is touched. The device checks (FileVault,
# firewall, backups) still run for real, so tests assert only on the rows they
# control.

emulate -L zsh
ROOT=${0:A:h:h}
BIN=$ROOT/seccheck

W=$(mktemp -d -t seccheck-test) || exit 1
cleanup() { [[ $W == */seccheck-test.* && -d $W ]] && rm -rf -- $W }
trap cleanup EXIT

typeset -i PASS=0 FAIL=0
ok()   { (( PASS++ )); print -- "  ok    $1" }
fail() { (( FAIL++ )); print -- "  FAIL  $1"; [[ -n $2 ]] && print -r -- "        $2" }
has()  { if [[ $2 == *$3* ]]; then ok $1; else fail $1 "wanted: $3 | got: $2"; fi }
hasnt(){ if [[ $2 != *$3* ]]; then ok $1; else fail $1 "did not want: $3 | got: $2"; fi }
eq()   { if [[ $2 == $3 ]]; then ok $1; else fail $1 "wanted: $3 | got: $2"; fi }

mkdir -p $W/bin $W/rdap
print -r -- '#!/bin/zsh
print -r -- "$*" >> $OSA_LOG' > $W/bin/osascript
chmod +x $W/bin/osascript

export PATH=$W/bin:$PATH OSA_LOG=$W/osa.log
export SECCHECK_CONF=$W/conf SECCHECK_STATE=$W/state SECCHECK_LANG=en
: > $OSA_LOG

conf() {  # conf <VPN_ORG_MATCH> [extra config lines…]
  {
    print -r -- "VPN_ORG_MATCH=\"$1\""
    print -r -- "IP_ENDPOINTS=(file://$W/exit.json)"
    print -r -- "RDAP_ENDPOINT=file://$W/rdap"
    shift
    for l in $@; do print -r -- $l; done
  } > $W/conf
}
exit_at() {  # exit_at <ip> [org]
  print -r -- "{\"ip\":\"$1\",\"city\":\"Amsterdam\",\"country\":\"NL\",\"org\":\"${2:-AS64500 Example Hosting}\"}" > $W/exit.json
}
exit_row() { $BIN $@ 2>&1 | grep 'Exit point' }
sent()     { wc -l < $OSA_LOG | tr -d ' ' }

print -r -- '{"name":"Examplenet","remarks":[{"description":["Examplenet Europe"]}]}' > $W/rdap/203.0.113.10
print -r -- '{"name":"SOME-ISP","remarks":[{"description":["Home broadband"]}]}'     > $W/rdap/203.0.113.20
print -r -- '{"name":"SOME-ISP","remarks":[{"description":["Home broadband"]}]}'     > $W/rdap/203.0.113.21

print -- "\nbasics"
zsh -n $BIN && ok "script parses" || fail "script parses"
eq "--version" "$($BIN --version)" "seccheck $(sed -n 's/^VERSION=//p' $BIN)"
has "--help prints usage" "$($BIN --help)" "usage: seccheck"
$BIN --no-such-flag >/dev/null 2>&1; eq "unknown option exits 64" $? 64
$BIN --install-agent soon >/dev/null 2>&1; eq "bad agent interval exits 64" $? 64

print -- "\nexit point"
conf "ExampleNet|ExampleVPN"
exit_at 203.0.113.5 "AS64501 ExampleVPN Ltd"
out=$(exit_row)
has "ASN names the provider -> ok" "$out" "✓"

exit_at 203.0.113.5 "AS64501 examplevpn ltd"
has "ASN match ignores case" "$(exit_row)" "✓"

exit_at 203.0.113.10
out=$(exit_row)
has "foreign ASN, registry names the provider -> ok" "$out" "✓"
has "block owner is shown" "$out" "block owner Examplenet"

exit_at 203.0.113.20
out=$(exit_row)
has "foreign ASN, foreign registry -> problem" "$out" "✗"
has "the address is shown in the alarm" "$out" "203.0.113.20"
$BIN >/dev/null 2>&1; eq "a problem makes the exit code 2" $? 2

exit_at 203.0.113.99
has "registry unreachable -> still a problem, no crash" "$(exit_row)" "✗"

conf "ExampleNet|ExampleVPN" "RDAP_ENDPOINT="
exit_at 203.0.113.10
has "registry disabled -> problem" "$(exit_row)" "✗"

conf ""
exit_at 203.0.113.10
out=$(exit_row)
has "no provider configured -> warning, not a pass" "$out" "!"
has "the warning says what to set" "$out" "VPN_ORG_MATCH"

conf "ExampleNet|ExampleVPN" "VPN_EXPECTED=0"
exit_at 203.0.113.20
has "VPN not expected -> exit point is informational" "$(exit_row)" "✓"
hasnt "VPN not expected -> route never alarms" "$($BIN 2>&1 | grep 'Route')" "✗"

has "--no-net skips the lookup" "$(exit_row --no-net)" "skipped"

print -- "\nfail-closed matching"
conf "ExampleNet|ExampleVPN"
exit_at 203.0.113.20 "AS64502 ExampleVPNet Telecom"
has "a longer word is not the provider" "$(exit_row)" "✗"

print -r -- '{"name":"SOME-ISP","notices":[{"description":["Peering with ExampleVPN"]}],"links":[{"href":"https://examplevpn.example/"}]}' > $W/rdap/203.0.113.30
exit_at 203.0.113.30
has "provider named outside the ownership fields -> problem" "$(exit_row)" "✗"

print -r -- '{"name":"NET-203","entities":[{"handle":"ORG-1","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","ExampleNet S.A."]]]}]}' > $W/rdap/203.0.113.31
exit_at 203.0.113.31
has "registrant entity names the provider -> ok" "$(exit_row)" "block owner ExampleNet"

print -r -- 'not json at all, but it says ExampleVPN' > $W/rdap/203.0.113.32
exit_at 203.0.113.32
has "unparseable registry answer -> problem" "$(exit_row)" "✗"

exit_at "203.0.113.20/../../x"
has "a non-address from the lookup service is not trusted" "$(exit_row)" "could not determine"

print -- "\ndevice"
mkdir -p $W/sip
print -r -- "#!/bin/zsh
cat $W/sip/out" > $W/sip/csrutil
chmod +x $W/sip/csrutil
sip_row() { PATH=$W/sip:$PATH $BIN --no-net 2>&1 | grep 'SIP' }

print -r -- 'System Integrity Protection status: enabled.' > $W/sip/out
has "SIP enabled -> ok" "$(sip_row)" "✓"
print -r -- 'System Integrity Protection status: disabled.' > $W/sip/out
has "SIP disabled -> problem" "$(sip_row)" "✗"
print -r -- 'System Integrity Protection status: unknown (Custom Configuration).

Configuration:
	Apple Internal: disabled
	Kext Signing: enabled
	Filesystem Protections: disabled
	Debugging Restrictions: enabled
	DTrace Restrictions: enabled
	NVRAM Protections: enabled
	BaseSystem Verification: enabled' > $W/sip/out
out=$(sip_row)
has "SIP custom configuration -> problem" "$out" "✗"
has "the row says it is a custom configuration" "$out" "custom"

print -- "\nnotifications"
conf "ExampleNet|ExampleVPN"
: > $OSA_LOG; : > $W/state
exit_at 203.0.113.20
$BIN --quiet --notify >/dev/null 2>&1
n1=$(sent)
(( n1 >= 1 )) && ok "a new problem notifies" || fail "a new problem notifies" "sent: $n1"
has "state has the exit problem" "$(cat $W/state)" "exit:AS64500 Example Hosting"
hasnt "state does not contain the address" "$(cat $W/state)" "203.0.113"

exit_at 203.0.113.21
$BIN --quiet --notify >/dev/null 2>&1
eq "same problem, new address -> silent" $(sent) $n1

$BIN --quiet --notify >/dev/null 2>&1
eq "unchanged state -> silent" $(sent) $n1

SECCHECK_LANG=uk $BIN --quiet --notify >/dev/null 2>&1
eq "switching language -> silent" $(sent) $n1

exit_at 203.0.113.10
$BIN --quiet --notify >/dev/null 2>&1
hasnt "a fixed problem leaves the state" "$(cat $W/state)" "exit:"

print -- "\nlanguage and output"
has "English labels" "$(SECCHECK_LANG=en $BIN --no-net 2>&1)" "NETWORK"
has "Ukrainian labels" "$(SECCHECK_LANG=uk $BIN --no-net 2>&1)" "МЕРЕЖА"
quiet=$($BIN --quiet --no-net 2>&1)
hasnt "--quiet hides passing rows" "$quiet" "✓"

if command -v python3 >/dev/null; then
  if $BIN --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["rows"] and all(r["status"] in ("ok", "warn", "bad") for r in d["rows"])
assert d["failures"] == sum(r["status"] == "bad" for r in d["rows"])
assert d["warnings"] == sum(r["status"] == "warn" for r in d["rows"])
'; then ok "--json is valid and consistent"; else fail "--json is valid and consistent"; fi
else
  print -- "  skip  --json validation (no python3)"
fi

print -- "\nconfig"
new=$W/fresh/seccheck.conf
SECCHECK_CONF=$new $BIN --init-config >/dev/null; eq "--init-config creates the file" $? 0
[[ -s $new ]] && zsh -n $new && ok "generated config is valid zsh" || fail "generated config is valid zsh"
print -r -- "# mine" >> $new
SECCHECK_CONF=$new $BIN --init-config >/dev/null; eq "--init-config refuses to overwrite" $? 1
has "existing config is left alone" "$(tail -1 $new)" "# mine"

print -- "\n$PASS passed, $FAIL failed"
(( FAIL == 0 ))

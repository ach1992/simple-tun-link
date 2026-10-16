#!/usr/bin/env bash
# Release installer for simple-tun-link. Does not create/remove Links or systemd units.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

usage() {
  cat >&2 <<'USAGE'
Usage:
  install.sh install --version vX.Y.Z [--prefix /usr/local]
  install.sh update --version vX.Y.Z [--prefix /usr/local]
  install.sh install|update --bundle /path/to/release-bundle [--prefix /usr/local]
  install.sh install|update --version vX.Y.Z [--backends native,wireguard,ipsec]
  install.sh install|update --bundle /path/to/release-bundle [--prefix /usr/local] [--backends all]
  install.sh requirements [--backends native,wireguard,ipsec] [--os-release-file /path/to/read-only-fixture]
  install.sh prepare --backends native|wireguard|ipsec|all [--expected-missing '...'] [--expected-apt-plan '...']
  install.sh uninstall [--prefix /usr/local]

The default backend selection is native (GRE/IPIP). Add wireguard and/or
ipsec explicitly to provision optional dependencies. "all" selects all.
IPsec on a verified clean systemd host may be prepared after a fresh, exact
package/dependency PREPARE consent. Distribution hooks can temporarily
start/enable a newly introduced strongSwan vendor service.
The prepare action installs only missing selected packages on an existing,
installer-owned /usr/local/bin/stl, without replacing STL or modifying Links.
Only the proven transaction-created vendor strongSwan service may be stopped
and disabled; pre-existing/foreign services are never modified. Private STL
service admission remains a separate verified step under the same UI consent.
No host Link or network configuration is modified by this installer.
--bundle is for locally built/tested bundles; system dependencies are
only installed on the real /usr/local prefix, never an offline test prefix.
USAGE
  exit 2
}
fail() { printf 'stl installer [FAILED]: %s\n' "$*" >&2; exit 1; }
[[ $# -ge 1 ]] || usage
action=$1
shift
case "$action" in install|update|uninstall|requirements|prepare) ;; *) usage ;; esac
prefix=/usr/local
version=
bundle=
backends=native
backends_supplied=0
os_release_fixture=
expected_missing=
expected_missing_supplied=0
expected_apt_plan=
expected_apt_plan_supplied=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) [[ $# -ge 2 && -z $version ]] || usage; version=$2; shift 2 ;;
    --bundle) [[ $# -ge 2 && -z $bundle ]] || usage; bundle=$2; shift 2 ;;
    --prefix) [[ $# -ge 2 ]] || usage; prefix=$2; shift 2 ;;
    --backends) [[ $# -ge 2 && $backends_supplied == 0 ]] || usage; backends=$2; backends_supplied=1; shift 2 ;;
    --os-release-file) [[ $# -ge 2 && -z $os_release_fixture ]] || usage; os_release_fixture=$2; shift 2 ;;
    --expected-missing) [[ $# -ge 2 && $expected_missing_supplied == 0 ]] || usage; expected_missing=$2; expected_missing_supplied=1; shift 2 ;;
    --expected-apt-plan) [[ $# -ge 2 && $expected_apt_plan_supplied == 0 ]] || usage; expected_apt_plan=$2; expected_apt_plan_supplied=1; shift 2 ;;
    *) usage ;;
  esac
done
if [[ $action == uninstall || $action == requirements || $action == prepare ]]; then
  [[ -z $version && -z $bundle ]] || usage
  [[ $action != uninstall || $backends_supplied == 0 ]] || usage
  [[ $action != prepare || $backends_supplied == 1 ]] || usage
else
  [[ -n $version && -z $bundle || -z $version && -n $bundle ]] || usage
fi
[[ $action == requirements || -z $os_release_fixture ]] || usage
[[ $action == prepare || ( $expected_missing_supplied == 0 && $expected_apt_plan_supplied == 0 ) ]] || usage
[[ $action != prepare || $prefix == /usr/local ]] || fail 'package preparation is allowed only for the installer-owned /usr/local installation'

# Use a data-only OS release parser. Never "source" /etc/os-release as shell
# code, and never accept caller-controlled OS paths for privileged installs.
read_os_value() {
  local path=$1 key=$2 line value= count=0
  [[ -f $path && -r $path ]] || fail "OS release file is unreadable: $path"
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "$key="* ]]; then
      ((count+=1))
      value=${line#*=}
    fi
  done < "$path"
  [[ $count == 1 ]] || fail "OS release must define $key exactly once"
  if [[ $value == \"*\" ]]; then value=${value:1:${#value}-2}; fi
  [[ $value =~ ^[a-zA-Z0-9._-]+$ ]] || fail "invalid $key in OS release"
  printf '%s' "$value"
}

validate_os() {
  local os_file=$1 major minor
  os_id=$(read_os_value "$os_file" ID)
  os_version=$(read_os_value "$os_file" VERSION_ID)
  case "$os_id" in
    debian)
      [[ $os_version =~ ^([0-9]+)(\.[0-9]+)?$ ]] || fail "invalid Debian version: $os_version"
      major=${BASH_REMATCH[1]}
      (( 10#$major >= 11 )) || fail "Debian 11 or later is required; found $os_version"
      if (( 10#$major == 11 )); then
        printf 'stl installer [WARNING]: Debian 11 LTS ended 2026-08-31; retain compatibility only with separately maintained security support. No APT source changes are made.\n' >&2
      fi
      ;;
    ubuntu)
      [[ $os_version =~ ^([0-9]+)\.([0-9]{2})$ ]] || fail "invalid Ubuntu version: $os_version"
      major=${BASH_REMATCH[1]}
      minor=${BASH_REMATCH[2]}
      (( 10#$major > 22 || (10#$major == 22 && 10#$minor >= 4) )) ||
        fail "Ubuntu 22.04 or later is required; found $os_version"
      ;;
    *) fail "unsupported distribution: $os_id $os_version; expected Ubuntu >=22.04 or Debian >=11" ;;
  esac
}

# Explicit backend selection prevents unexpectedly provisioning an IPsec
# daemon on a host that already has another strongSwan deployment.
select_packages() {
  local item
  local -a requested=()
  want_native=0
  want_wg=0
  want_ipsec=0
  [[ $backends =~ ^[a-z,]+$ ]] || usage
  # Bash read -a silently discards an empty trailing CSV item.
  [[ $backends != ,* && $backends != *, && $backends != *,,* ]] || usage
  IFS=',' read -ra requested <<< "$backends"
  [[ ${#requested[@]} -gt 0 ]] || usage
  for item in "${requested[@]}"; do
    case "$item" in
      native) [[ $want_native == 0 ]] || usage; want_native=1 ;;
      wireguard) [[ $want_wg == 0 ]] || usage; want_wg=1 ;;
      ipsec) [[ $want_ipsec == 0 ]] || usage; want_ipsec=1 ;;
      all)
        [[ ${#requested[@]} == 1 ]] || usage
        want_native=1
        want_wg=1
        want_ipsec=1
        ;;
      *) usage ;;
    esac
  done
  # iproute2/iptables are the Engine/network baseline. The kmod tools
  # provide the exact modinfo/modprobe commands used by the newly explicit
  # optional module preflight. This is not permission to load all modules.
  packages=(iproute2 iptables kmod)
  [[ $want_wg == 0 ]] || packages+=(wireguard-tools)
  # The standard plugin bundle supplies common cryptographic backends such
  # as OpenSSL/GCM; --no-install-recommends would omit it otherwise.
  [[ $want_ipsec == 0 ]] || packages+=(charon-systemd strongswan-swanctl libstrongswan-standard-plugins)
}

package_installed() {
  local result
  result=$(dpkg-query -W -f='${Status}' -- "$1" 2>/dev/null) || return 1
  [[ $result == 'install ok installed' ]]
}

# Verify the source of each SELECTED candidate, not merely its APT-trusted
# Release Origin/Label. A third-party source may sign its own Release metadata
# with a trusted key and claim "Ubuntu" or "Debian". The signed InRelease that
# backs the precise candidate Packages index must instead verify against the
# distribution's installed archive-keyring trust anchor. This does not edit
# source lists, add keys or relax APT's own signature/hash verification.
apt_verify_distro_candidates() {
  local anchor keyring_package index_targets row description filename component architecture
  local target identifier release suffix index_file pkg_version pkg version policy_line selected=0
  local source candidate=0 matches policy
  local -A indices=() release_verified=()
  if [[ $os_id == ubuntu ]]; then
    anchor=/usr/share/keyrings/ubuntu-archive-keyring.gpg
    keyring_package=ubuntu-keyring
  else
    anchor=/usr/share/keyrings/debian-archive-keyring.gpg
    keyring_package=debian-archive-keyring
  fi
  [[ -r $anchor && -f $anchor && $(stat -Lc %u "$anchor") == 0 ]] ||
    fail 'official distribution archive signing keyring unavailable'
  [[ $(dpkg-query -S "$anchor" 2>/dev/null) == "$keyring_package: "* ]] ||
    fail 'official archive keyring package ownership unverified'
  package_installed "$keyring_package" || fail 'distribution archive keyring package not fully installed'
  command -v gpgv >/dev/null || fail 'cannot verify distribution archive signatures'
  # indextargets reports the exact local Packages indices APT associates
  # with the configured sources. Match its Description to apt-cache policy's
  # per-version source line; never accept a matching label alone.
  index_targets=$(LC_ALL=C apt-get indextargets) ||
    fail 'APT index-to-release inventory could not be inspected'
  description= filename= component= architecture= target= identifier=
  while IFS= read -r row || [[ -n $row ]]; do
    if [[ -n $row ]]; then
      case "$row" in
        'Description: '*) description=${row#Description: } ;;
        'Filename: '*) filename=${row#Filename: } ;;
        'Component: '*) component=${row#Component: } ;;
        'Architecture: '*) architecture=${row#Architecture: } ;;
        'Target-Of: '*) target=${row#Target-Of: } ;;
        'Identifier: '*) identifier=${row#Identifier: } ;;
      esac
      continue
    fi
    if [[ $target == deb && $identifier == Packages && -n $description && -n $filename &&
          -n $component && -n $architecture ]]; then
      suffix="_${component}_binary-${architecture}_Packages"
      # Debian reports logical filenames; Ubuntu may report compressed .lz4
      # package-index paths from apt-get indextargets. Strip known APT formats.
      index_file=$filename
      case "$index_file" in
        *.lz4|*.xz|*.gz|*.zst|*.bz2) index_file="${index_file%.*}" ;;
      esac
      # Skip NONSELECTED index targets that have no signed release mapping.
      # The selected candidate below always fails if its mapping is absent.
      if [[ $index_file != /var/lib/apt/lists/* || $index_file != *"$suffix" ]]; then
        description= filename= component= architecture= target= identifier=
        continue
      fi
      release="${index_file%"$suffix"}_InRelease"
      # The mapped InRelease must be local and immutable by non-root users;
      # its actual cryptographic signer is checked only if selected by APT.
      if [[ -n ${indices[$description]+present} ]]; then
        [[ ${indices[$description]} == "$release" ]] ||
          fail 'APT candidate source maps to ambiguous release identities'
      else
        indices["$description"]=$release
      fi
    fi
    description= filename= component= architecture= target= identifier=
  done <<< "$index_targets"$'\n'
  [[ ${#indices[@]} -gt 0 ]] || fail 'no APT package index mapping available'
  for pkg_version in "${planned[@]}"; do
    pkg=${pkg_version%%=*}
    version=${pkg_version#*=}
    selected=0
    candidate=0
    matches=0
    policy=$(LC_ALL=C apt-cache policy -- "$pkg") ||
      fail 'APT candidate-to-index policy could not be read'
    while IFS= read -r policy_line; do
      if [[ $policy_line == '  Candidate: '* ]]; then
        [[ ${policy_line#  Candidate: } == "$version" ]] ||
          fail 'APT preferred candidate differs from the consented version'
        candidate=1
      elif [[ $policy_line =~ ^[[:space:]]+(\*\*\*[[:space:]]+)?([^[:space:]]+)[[:space:]]+-?[0-9]+$ ]]; then
        [[ ${BASH_REMATCH[2]} == "$version" ]] && selected=1 || selected=0
      elif [[ $selected == 1 && $policy_line =~ ^[[:space:]]+[0-9]+[[:space:]]+(.+[[:space:]]Packages)$ ]]; then
        source=${BASH_REMATCH[1]}
        [[ -n ${indices[$source]+present} ]] ||
          fail 'APT candidate includes a non-distribution package source'
        release=${indices[$source]}
        if [[ -z ${release_verified[$release]+present} ]]; then
          [[ -f $release && ! -L $release && $(stat -c %u "$release") == 0 ]] ||
            fail 'APT candidate InRelease is missing or untrusted'
          gpgv --quiet --keyring "$anchor" "$release" >/dev/null 2>&1 ||
            fail 'APT candidate InRelease is not signed by the distribution archive'
          # A verified signer is decisive. These metadata fields are just an
          # additional consistency check, never an alternative to the key.
          if [[ $os_id == ubuntu ]]; then
            grep -qx 'Origin: Ubuntu' "$release" ||
              fail 'official Ubuntu archive metadata does not match the host'
          else
            grep -qx 'Origin: Debian' "$release" ||
              fail 'official Debian archive metadata does not match the host'
          fi
          release_verified["$release"]=1
        fi
        ((matches+=1))
      fi
    done <<< "$policy"
    [[ $candidate == 1 && $matches -gt 0 ]] ||
      fail 'APT candidate package version has no verified distribution index'
  done
}

# Read-only APT resolver: give the operator the complete install/dependency
# set BEFORE consent, and forbid upgrades, removals or unresolved candidates.
# APT signature checks remain mandatory at execution; never allow insecure,
# unauthenticated or trusted=yes repository shortcuts.
apt_safety=(-o APT::Get::AllowUnauthenticated=false
            -o Acquire::AllowInsecureRepositories=false
            -o Acquire::AllowDowngradeToInsecureRepositories=false
            -o APT::Get::AllowRemoveEssential=false
            -o APT::Get::AllowChangeHeldPackages=false)
apt_resolve_plan() {
  local text line pkg version requested found
  local -a planned=()
  apt_plan=
  (( ${#missing[@]} > 0 )) || return 0
  text=$(LC_ALL=C apt-get -s -o Debug::NoLocking=1 "${apt_safety[@]}" \
    install --no-install-recommends -- "${missing[@]}") ||
    fail 'APT cannot resolve the complete selected dependency plan; no packages changed'
  while IFS= read -r line; do
    case "$line" in
      Remv\ *|Purg\ *) fail 'APT plan would remove packages; no changes allowed' ;;
      Inst\ *)
        [[ $line =~ ^Inst[[:space:]]+([a-z0-9][a-z0-9+.-]*(:[a-z0-9-]+)?)[[:space:]] ]] ||
          fail 'APT returned an unrecognized install identity'
        pkg=${BASH_REMATCH[1]}
        [[ $line =~ \(([0-9][A-Za-z0-9:.+~_-]*)[[:space:]] ]] ||
          fail 'APT returned an unrecognized candidate version'
        version=${BASH_REMATCH[1]}
        # For IPsec, never promote merely APT-trusted third-party packages
        # into "signed distro packages". The selected candidate must be
        # labeled Debian / Debian-Security / Ubuntu by APT, in addition to
        # APT's authenticated repository index and package checksum gates.
        if [[ $want_ipsec == 1 ]]; then
          case "$line" in
            *" Debian:"*|*" Debian-Security:"*|*" Ubuntu:"*) ;;
            *) fail 'APT selected an IPsec dependency outside the distro archive; no changes allowed' ;;
          esac
        fi
        if package_installed "$pkg"; then
          fail 'APT plan would upgrade an installed package; review separately'
        fi
        for requested in "${planned[@]}"; do
          [[ $requested != "$pkg="* ]] || fail 'APT plan includes duplicate package identity'
        done
        planned+=("$pkg=$version")
        ;;
    esac
  done <<< "$text"
  for requested in "${missing[@]}"; do
    found=0
    for pkg in "${planned[@]}"; do
      [[ $pkg != "$requested="* ]] || found=1
    done
    [[ $found == 1 ]] || fail 'APT plan omitted a required selected package'
  done
  apt_plan="${planned[*]}"
  [[ -n $apt_plan && ${#apt_plan} -lt 16384 ]] ||
    fail 'APT plan is empty or exceeds safe preview limits'
  [[ $want_ipsec == 0 ]] || apt_verify_distro_candidates
}

# StrongSwan candidates must originate from signed Debian/Ubuntu archives.
# apt-get itself verifies repository metadata and package hashes at execution.
# Reject local APT source shortcuts which deliberately bypass that guarantee.
apt_sources_must_be_authenticated() {
  local file
  for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list \
              /etc/apt/sources.list.d/*.sources; do
    [[ -f $file ]] || continue
    if grep -Eiq '(^|[[:space:]\[])trusted[[:space:]]*=[[:space:]]*yes([[:space:]\]]|$)|^[[:space:]]*Trusted:[[:space:]]*yes' "$file"; then
      fail 'APT sources explicitly bypass signature verification'
    fi
  done
}

# Reconcile the real system manager's effective UnitPath against a bounded
# distro-supported system-unit path set. Use the SAME inventory before distro
# package hooks, after APT and in read-only interruption diagnosis. An unknown
# manager path (including a SYSTEMD_UNIT_PATH override) is NOT a clean host.
# /lib is retained as the distro usr-merge compatibility spelling.
ipsec_system_unit_paths() {
  local report path allowed matched=0 has_etc=0 has_vendor=0
  local -a effective_paths=()
  local -A seen=()
  ipsec_system_unit_dirs=(
    /etc/systemd/system.control /run/systemd/system.control
    /run/systemd/transient /run/systemd/generator.early
    /etc/systemd/system /etc/systemd/system.attached
    /run/systemd/system /run/systemd/system.attached
    /run/systemd/generator /usr/local/lib/systemd/system
    /lib/systemd/system /usr/lib/systemd/system
    /run/systemd/generator.late
  )
  report=$(systemctl --system --no-pager show -p UnitPath 2>/dev/null) || return 1
  [[ $report == UnitPath=* && $report != *$'\n'* ]] || return 1
  report=${report#UnitPath=}
  [[ -n $report ]] || return 1
  read -r -a effective_paths <<< "$report"
  [[ ${#effective_paths[@]} -gt 0 ]] || return 1
  for path in "${effective_paths[@]}"; do
    [[ $path == /* ]] || return 1
    matched=0
    for allowed in "${ipsec_system_unit_dirs[@]}"; do
      if [[ $path == "$allowed" ]]; then matched=1; break; fi
    done
    [[ $matched == 1 && -z ${seen[$path]+present} ]] || return 1
    seen["$path"]=1
    [[ $path != /etc/systemd/system ]] || has_etc=1
    case "$path" in
      /lib/systemd/system|/usr/lib/systemd/system) has_vendor=1 ;;
    esac
  done
  [[ $has_etc == 1 && $has_vendor == 1 ]] || return 1
  # An unexpected unreadable/non-directory unit path cannot prove absence.
  for path in "${ipsec_system_unit_dirs[@]}"; do
    [[ -e $path || -L $path ]] || continue
    [[ -d $path && -r $path && -x $path ]] || return 1
  done
  return 0
}

# systemd merges drop-ins from a unit's real name, aliases, type-wide
# service.d/, and dash-prefix names. A post-APT DropInPaths check is too late
# if maintainer hooks briefly start a vendor service. Reject every applicable
# pre-existing override before allowing APT, including an alias that the
# package may not have created yet (strongswan-swanctl.service).
ipsec_reject_applicable_dropins() {
  local dir name
  ipsec_system_unit_paths ||
    fail 'systemd effective unit search paths unverified or unsupported; no APT attempted'
  for dir in "${ipsec_system_unit_dirs[@]}"; do
    for name in service.d strongswan.service.d strongswan-swanctl.service.d \
                strongswan-starter.service.d strongswan-.service.d \
                charon-systemd.service.d charon-.service.d ipsec.service.d \
                simple-tun-link-ipsec.service.d simple-tun-link-.service.d \
                simple-tun-.service.d simple-.service.d; do
      [[ ! -e "$dir/$name" && ! -L "$dir/$name" ]] ||
        fail 'pre-existing systemd service/alias/prefix override requires reconciliation'
    done
  done
}

# Classify ONLY the harmless one-line in-memory placeholder for STL's
# own as-yet-uninstalled private service. This matches Go's independently
# checked nativeProvisionInventoryUnoccupied boundary; no service, vendor,
# alias, loaded unit or extra output is adopted. A missing final newline,
# control/non-ASCII bytes or additional line fails closed.
ipsec_only_not_found_private_placeholder() {
  local raw=$1 line
  local LC_ALL=C
  local -a fields=()
  [[ ${#raw} -le 1024 && $raw == *$'\n' ]] || return 1
  line=${raw%$'\n'}
  [[ -n $line && $line != *$'\n'* && $line != *[![:print:]]* ]] || return 1
  read -r -a fields <<< "$line"
  [[ ${#fields[@]} -ge 5 &&
     ${fields[0]} == simple-tun-link-ipsec.service &&
     ${fields[1]} == not-found &&
     ${fields[2]} == inactive &&
     ${fields[3]} == dead ]]
}

# Conservative CLEAN-host boundary before any strongSwan package hooks.
# A pre-existing unit (including a disabled or masked one) is NEVER owned.
# This is intentionally eligibility for first install, not foreign-service
# remediation. The existing Go provisioner separately admits the STL unit.
ipsec_clean_host_before_apt() {
  local item dir unit proc line list
  [[ $EUID == 0 && -d /run/systemd/system ]] ||
    fail 'automatic IPsec requires a running root systemd host'
  [[ ! -e /var/lib/simple-tun-link/ipsec && ! -L /var/lib/simple-tun-link/ipsec ]] ||
    fail 'existing STL-private IPsec state requires reconciliation before APT'
  apt_sources_must_be_authenticated
  ipsec_reject_applicable_dropins
  [[ -z $(dpkg --audit) ]] || fail 'dpkg has unfinished package configuration; repair before IPsec preparation'
  for item in charon-systemd strongswan-swanctl libstrongswan-standard-plugins; do
    package_installed "$item" && fail 'partial strongSwan installation is not eligible for clean-host preparation'
  done
  # Foreign partial/alternate distro packages must not be adopted.
  while IFS= read -r line; do
    [[ $line != *$'\tinstall ok installed' ]] ||
      fail 'a foreign/alternate strongSwan package is installed'
  done < <(dpkg-query -W -f='${binary:Package}\t${Status}\n' \
              'charon*' 'strongswan*' 'libstrongswan*' 2>/dev/null || true)
  for item in /etc/strongswan.conf /etc/strongswan.d /etc/swanctl \
              /etc/ipsec.conf /etc/ipsec.secrets /etc/ipsec.d; do
    [[ ! -e $item && ! -L $item ]] ||
      fail 'pre-existing strongSwan/IPsec configuration is not STL-owned'
  done
  for unit in strongswan.service strongswan-swanctl.service \
              strongswan-starter.service charon-systemd.service \
              ipsec.service simple-tun-link-ipsec.service; do
    for dir in "${ipsec_system_unit_dirs[@]}"; do
      [[ ! -e "$dir/$unit" && ! -L "$dir/$unit" &&
         ! -e "$dir/$unit.d" && ! -L "$dir/$unit.d" ]] ||
        fail 'an existing vendor/STL systemd unit or override is present'
      # Boot edges may be placed in any manager-searchable unit directory.
      for edge in "$dir"/*.wants "$dir"/*.requires; do
        [[ ! -e "$edge/$unit" && ! -L "$edge/$unit" ]] ||
          fail 'a pre-existing vendor/STL service boot edge is present'
      done
    done
  done
  # A read-only status/doctor query can leave one in-memory systemd
  # LOAD=not-found placeholder for STL's future private unit. Unlike a
  # loaded or foreign service, this does NOT occupy a unit definition.
  # Capture a sentinel to preserve the command's trailing newline: Bash
  # command substitution normally strips it, obscuring malformed output.
  # Combined stdout/stderr must match a strict, single expected record;
  # an error or any additional vendor/foreign unit still blocks APT.
  list=$(systemctl --system --no-pager --no-legend --plain --all \
    --type=service list-units 'strongswan*.service' 'charon*.service' \
    'ipsec.service' 'simple-tun-link-ipsec.service' 2>&1 &&
    printf '\036') ||
    fail 'systemd existing loaded units could not be inventoried'
  [[ $list == *$'\036' ]] ||
    fail 'systemd loaded-unit output was incomplete'
  list=${list%$'\036'}
  if [[ -n $list ]]; then
    if ! ipsec_only_not_found_private_placeholder "$list"; then
      printf 'STL IPsec next: inspect loaded units and unit files with systemctl; any real/foreign unit must be reconciled before PREPARE. Never blindly stop another VPN.\n' >&2
      fail 'pre-existing or ambiguous strongSwan/IPsec service identity detected'
    fi
  fi
  # systemctl list-unit-files with a glob returns exit 1 when NO unit
  # matched on Ubuntu/systemd 255, even though the manager query succeeded.
  # Accept that exact negative only after the independent earlier successful
  # list-units query and only with completely empty stdout/stderr.
  local rc=0
  list=$(systemctl --system --no-pager --no-legend --plain list-unit-files \
    'strongswan*.service' 'charon*.service' 'ipsec.service' \
    'simple-tun-link-ipsec.service' 2>&1) || rc=$?
  [[ ( $rc == 0 || $rc == 1 ) && -z $list ]] ||
    fail 'systemd vendor unit-file inventory unavailable or occupied'
  for proc in /proc/[0-9]*/comm; do
    [[ -r $proc ]] || continue
    IFS= read -r item < "$proc" || continue
    case "$item" in
      charon|charon-systemd|starter|ipsec) fail 'foreign IKE process already running' ;;
    esac
  done
  for item in /proc/net/udp /proc/net/udp6; do
    [[ -r $item ]] || fail 'kernel UDP socket inventory unavailable'
    awk 'NR>1 { split($2, a, ":"); p=a[length(a)]; if(p=="01F4" || p=="1194") exit 42 }' "$item" ||
      fail 'IKE UDP 500/4500 is occupied or cannot be inspected'
  done
}

# Only strongswan.service installed *by this verified transaction* is
# eligible for vendor normalization. Package files, effective systemd source
# and absence of foreign drop-ins must agree before ANY stop/disable.
ipsec_normalize_new_vendor() {
  local unit=strongswan.service fragment meta enable active owner
  meta=$(systemctl --system --no-pager show "$unit" \
    -p FragmentPath -p SourcePath -p DropInPaths -p NeedDaemonReload) ||
    fail 'new vendor service could not be inspected after APT'
  fragment=$(sed -n 's/^FragmentPath=//p' <<< "$meta")
  [[ $fragment == /lib/systemd/system/strongswan.service ||
     $fragment == /usr/lib/systemd/system/strongswan.service ]] ||
    fail 'installed vendor unit path is unknown; no foreign unit will be modified'
  [[ $(grep -c '^FragmentPath=' <<< "$meta") == 1 &&
     $(grep -c '^SourcePath=$' <<< "$meta") == 1 &&
     $(grep -c '^DropInPaths=$' <<< "$meta") == 1 &&
     $(grep -c '^NeedDaemonReload=no$' <<< "$meta") == 1 ]] ||
    fail 'new vendor unit has an unexpected effective source, drop-in or pending reload'
  owner=$(dpkg-query -S "$fragment" 2>/dev/null || dpkg-query -S \
    "/lib/systemd/system/strongswan.service" 2>/dev/null) ||
    fail 'new vendor unit is not owned by an installed distro package'
  [[ $owner == "charon-systemd: "* ]] ||
    fail 'vendor unit belongs to a foreign package; no service modified'
  # Validate the new vendor alias itself as well as all systemd drop-in
  # identities. A package-created alias is permitted only when it resolves to
  # the already attested distro-owned fragment; a regular/foreign unit is not.
  ipsec_reject_applicable_dropins
  local dir alias meta_alias alias_fragment
  for dir in "${ipsec_system_unit_dirs[@]}"; do
    alias="$dir/strongswan-swanctl.service"
    if [[ -e $alias || -L $alias ]]; then
      [[ -L $alias && $(readlink -f -- "$alias") == "$(readlink -f -- "$fragment")" ]] ||
        fail 'vendor alias does not target the verified distro unit'
    fi
  done
  # Also ask systemd about the effective alias identity: it combines alias
  # drop-ins into the main unit and must not expose another loaded fragment.
  meta_alias=$(systemctl --system --no-pager show strongswan-swanctl.service \
    -p FragmentPath -p DropInPaths) ||
    fail 'new vendor alias cannot be inspected after APT'
  alias_fragment=$(sed -n 's/^FragmentPath=//p' <<< "$meta_alias")
  [[ -z $alias_fragment || "$(readlink -f -- "$alias_fragment")" == "$(readlink -f -- "$fragment")" ]] ||
    fail 'effective vendor alias points at a foreign service'
  [[ $(grep -c '^DropInPaths=$' <<< "$meta_alias") == 1 ]] ||
    fail 'effective vendor alias contains a foreign drop-in'
  # Reject unforeseen alternate identities rather than touching them.
  for item in strongswan-starter.service charon-systemd.service ipsec.service; do
    [[ ! -e /etc/systemd/system/$item && ! -L /etc/systemd/system/$item ]] ||
      fail 'a second vendor service identity appeared; reconciliation required'
  done
  active=$(systemctl --system --no-pager is-active "$unit" 2>/dev/null) || :
  enable=$(systemctl --system --no-pager is-enabled "$unit" 2>/dev/null) || :
  [[ $active == active || $active == inactive ]] ||
    fail 'new vendor runtime state is ambiguous after APT'
  [[ $enable == enabled || $enable == disabled ]] ||
    fail 'new vendor boot enablement state is ambiguous after APT'
  if [[ $active == active ]]; then
    systemctl --system stop "$unit" ||
      fail 'transaction-created vendor service could not be stopped; inspect persistent package effects'
  fi
  if [[ $enable == enabled ]]; then
    systemctl --system disable "$unit" ||
      fail 'transaction-created vendor service could not be disabled; inspect persistent package effects'
  fi
  [[ $(systemctl --system --no-pager is-active "$unit" 2>/dev/null || :) == inactive &&
     $(systemctl --system --no-pager is-enabled "$unit" 2>/dev/null || :) == disabled ]] ||
    fail 'new vendor service remains active or boot-enabled after preparation'
  for item in /proc/net/udp /proc/net/udp6; do
    awk 'NR>1 { split($2, a, ":"); p=a[length(a)]; if(p=="01F4" || p=="1194") exit 42 }' "$item" ||
      fail 'IKE UDP owner remains after vendor normalization'
  done
  printf '[OK] Transaction-created strongSwan vendor service inactive and disabled.\n' >&2
}

# APT can fail AFTER dpkg hooks have already installed/enabled/started the
# new vendor service. Never pretend those changes were rolled back or perform
# a blind retry. Only read dpkg/systemd identity and report the observed
# recovery boundary; in particular no service is stopped on an uncertain
# package transaction and STL-private service admission never begins.
ipsec_report_interrupted_apt() {
  local pkg_version pkg status audit audit_result vendor_active vendor_enabled fragment alias_state
  local installed=0 partial=0 absent=0 unknown=0
  audit_result=unknown
  if audit=$(dpkg --audit 2>/dev/null); then
    if [[ -z $audit ]]; then audit_result=clean; else audit_result=incomplete; fi
  fi
  for pkg_version in "${pinned_install[@]}"; do
    pkg=${pkg_version%%=*}
    status=$(dpkg-query -W -f='${Status}' -- "$pkg" 2>/dev/null) || status=
    case "$status" in
      'install ok installed') ((installed+=1)) ;;
      '') ((absent+=1)) ;;
      *'unpacked'*|*'half-configured'*|*'half-installed'*|*'triggers-'*) ((partial+=1)) ;;
      *) ((unknown+=1)) ;;
    esac
  done
  vendor_active=$(systemctl --system --no-pager is-active strongswan.service 2>/dev/null) || :
  vendor_enabled=$(systemctl --system --no-pager is-enabled strongswan.service 2>/dev/null) || :
  fragment=$(systemctl --system --no-pager show strongswan.service -p FragmentPath 2>/dev/null) || fragment=
  # A single /etc location cannot establish alias absence. The manager
  # might resolve the alias from an attached, transient or generated unit.
  # Failure to attest the complete load-path inventory means UNKNOWN.
  alias_state=unknown
  if ipsec_system_unit_paths; then
    alias_state=absent
    local dir
    for dir in "${ipsec_system_unit_dirs[@]}"; do
      if [[ -e "$dir/strongswan-swanctl.service" ||
            -L "$dir/strongswan-swanctl.service" ||
            -e "$dir/strongswan-swanctl.service.d" ||
            -L "$dir/strongswan-swanctl.service.d" ]]; then
        alias_state=present_unverified
        break
      fi
    done
  fi
  printf 'STL_IPSEC_APT_RECOVERY dpkg_audit=%s planned_installed=%s planned_partial=%s planned_absent=%s planned_unknown=%s\n' \
    "$audit_result" "$installed" "$partial" "$absent" "$unknown" >&2
  printf 'STL_IPSEC_APT_RECOVERY vendor_active=%s vendor_enabled=%s vendor_fragment=%s alias=%s\n' \
    "${vendor_active:-unknown}" "${vendor_enabled:-unknown}" \
    "${fragment#FragmentPath=}" "$alias_state" >&2
  printf 'STL_IPSEC_APT_RECOVERY result=RECONCILIATION_REQUIRED retry=BLOCKED private_service=NOT_STARTED link=NOT_CREATED\n' >&2
  printf 'STL next: run sudo stl doctor ipsec and reconcile dpkg/vendor state before a new PREPARE; no automatic retry or rollback.\n' >&2
}

ensure_packages() {
  local pkg missing_ipsec=0 before_plan
  local -a missing=()
  command -v apt-get >/dev/null && command -v dpkg-query >/dev/null ||
    fail 'apt-get and dpkg-query are required on supported distributions'
  for pkg in "${packages[@]}"; do
    package_installed "$pkg" || missing+=("$pkg")
  done
  if [[ $expected_missing_supplied == 1 && "${missing[*]}" != "$expected_missing" ]]; then
    fail 'selected package inventory changed since confirmation; no APT attempted'
  fi
  if (( ${#missing[@]} == 0 )); then
    [[ $expected_apt_plan_supplied == 0 || -z $expected_apt_plan ]] ||
      fail 'APT plan changed since confirmation; no APT attempted'
    printf '[OK] STL dependencies already installed for %s %s (%s).\n' "$os_id" "$os_version" "$backends" >&2
    return
  fi
  if [[ $want_ipsec == 1 ]]; then
    for pkg in "${missing[@]}"; do
      case "$pkg" in charon-systemd|strongswan-swanctl|libstrongswan-standard-plugins) missing_ipsec=1 ;; esac
    done
  fi
  if [[ $missing_ipsec == 1 && ( $action != prepare ||
        $expected_missing_supplied != 1 || $expected_apt_plan_supplied != 1 ) ]]; then
    fail 'automatic IPsec requires explicit exact-plan PREPARE consent'
  fi
  if [[ $missing_ipsec == 1 ]]; then
    # Even APT simulation must not run before a pre-existing vendor/service
    # conflict is excluded under the canonical installer maintenance lock.
    ipsec_clean_host_before_apt
  fi
  # The initial binary install can run on a fresh OS whose APT index is
  # deliberately empty. It has no menu dependency preview to preserve, so
  # initialize authenticated metadata BEFORE resolving ordinary dependencies.
  # Already-installed STL "prepare" must instead compare its prior read-only
  # exact plan, refresh indexes and refuse any changed plan.
  if [[ $action != prepare ]]; then
    DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none       apt-get "${apt_safety[@]}" -o Acquire::Retries=2 update ||
      fail 'APT index refresh failed before initial dependency install'
  fi
  apt_resolve_plan
  before_plan=$apt_plan
  if [[ $expected_apt_plan_supplied == 1 && $before_plan != "$expected_apt_plan" ]]; then
    fail 'APT dependency plan changed since confirmation; no APT attempted'
  fi
  if [[ $missing_ipsec == 1 ]]; then
    ipsec_clean_host_before_apt
  fi
  printf '[INFO] Installing verified missing packages on %s %s: %s\n' "$os_id" "$os_version" "$before_plan" >&2
  if [[ $action == prepare ]]; then
    DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none       apt-get "${apt_safety[@]}" -o Acquire::Retries=2 update ||
      fail 'APT index refresh failed; inspect package indexes before retry'
    apt_resolve_plan
    [[ $apt_plan == "$before_plan" ]] ||
      fail 'APT dependency plan changed after index refresh; package install cancelled'
  fi
  if [[ $missing_ipsec == 1 ]]; then
    ipsec_clean_host_before_apt
  fi
  # Enforce the exact package=version transaction the operator reviewed.
  # Passing only the selected top-level names would let APT choose a newer
  # transitive candidate between preview and execution.
  local -a pinned_install=()
  read -r -a pinned_install <<< "$before_plan"
  [[ ${#pinned_install[@]} -gt 0 ]] ||
    fail 'approved APT install plan is empty; nothing installed'
  local apt_status=0
  DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \
    apt-get "${apt_safety[@]}" install -y --no-install-recommends -- "${pinned_install[@]}" || apt_status=$?
  if (( apt_status != 0 )); then
    if [[ $missing_ipsec == 1 ]]; then
      ipsec_report_interrupted_apt
    fi
    fail 'APT transaction incomplete; no Link created and no automatic retry'
  fi
  for pkg in "${packages[@]}"; do
    package_installed "$pkg" || fail "selected package remains unavailable: $pkg"
  done
  if [[ $missing_ipsec == 1 ]]; then
    ipsec_normalize_new_vendor
  fi
}

select_packages
if [[ $action == requirements ]]; then
  validate_os "${os_release_fixture:-/etc/os-release}"
  printf 'distribution=%s\nversion=%s\nselected_backends=%s\npackages=%s\n'     "$os_id" "$os_version" "$backends" "${packages[*]}"
  # Optional live-host, read-only observation for the binary-embedded menu
  # preparer. A caller-supplied OS fixture must not be mixed with host dpkg.
  # This is a preview, not proof that the installed package set cannot race.
  if [[ -z $os_release_fixture ]]; then
    command -v dpkg-query >/dev/null || fail 'cannot inspect installed packages'
    missing=()
    for pkg in "${packages[@]}"; do
      package_installed "$pkg" || missing+=("$pkg")
    done
    printf 'missing_packages=%s\n' "${missing[*]}"
    apt_resolve_plan
    printf 'apt_install=%s\n' "$apt_plan"
  fi
  if [[ $want_ipsec == 1 ]]; then
    printf 'notice=IPsec PREPARE may briefly activate a new vendor strongSwan service; only transaction-owned service normalization is permitted\n'
  fi
  exit 0
fi
if [[ -n $version ]]; then
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]] || usage
fi
[[ $(uname -s) == Linux ]] || fail 'STL installer supports Linux only'
[[ $prefix == /* && $prefix != / && -d $prefix && ! -L $prefix ]] || fail 'prefix must be an existing absolute non-symlink directory'
[[ "$(realpath -e -- "$prefix")" == "$prefix" ]] || fail 'prefix must be canonical (no symlinks or dot segments)'
# Nondefault prefixes are isolated/offline test or custom local installations.
[[ $prefix == /usr/local || -n $bundle || $action == uninstall ]] || fail 'a nondefault prefix requires an offline --bundle'
[[ $prefix != /usr/local || $EUID -eq 0 ]] || fail 'installation to /usr/local requires root'
if [[ $prefix == /usr/local && $action != uninstall ]]; then
  # Fail early, before installing files or packages, on unsupported systems.
  validate_os /etc/os-release
fi
bin_dir="$prefix/bin"
record_dir="$prefix/lib/simple-tun-link"
target="$bin_dir/stl"
alias="$bin_dir/stlink"
record="$record_dir/install-record"
lock="$record_dir/.maintenance.lock"
[[ -d $bin_dir && ! -L $bin_dir && -d $prefix/lib && ! -L $prefix/lib ]] || fail 'prefix must already contain safe bin and lib directories'

# Default system-wide install must not traverse a writable or unowned directory.
if [[ $prefix == /usr/local ]]; then
  for path in / /usr /usr/local "$bin_dir" "$prefix/lib"; do
    [[ ! -L $path && -d $path && $(stat -c %u -- "$path") == 0 ]] || fail "untrusted installation directory: $path"
    perms=$(stat -c %a -- "$path")
    [[ $perms =~ ^[0-7]{3,4}$ ]] && (( (8#$perms & 8#022) == 0 )) || fail "installation directory is writable by non-root: $path"
  done
fi

if [[ $action != install ]]; then
  [[ -d $record_dir && ! -L $record_dir ]] || fail 'no STL installer-owned installation found'
fi
if [[ ! -e $record_dir ]]; then
  mkdir -m 0700 -- "$record_dir" || fail 'cannot create installer-owned metadata directory'
fi
[[ -d $record_dir && ! -L $record_dir ]] || fail 'untrusted installer metadata directory'
if [[ $prefix == /usr/local ]]; then
  [[ $(stat -c %u -- "$record_dir") == 0 ]] || fail 'installer metadata must be root-owned'
  perms=$(stat -c %a -- "$record_dir")
  [[ $perms =~ ^[0-7]{3,4}$ ]] && (( (8#$perms & 8#077) == 0 )) || fail 'installer metadata directory must be private'
fi
[[ ! -L $lock && ( ! -e $lock || -f $lock ) ]] || fail 'unsafe installer lock identity'
exec 9>>"$lock"
flock -x -w 30 9 || fail 'another STL installer is running'
is_regular() { [[ -f $1 && ! -L $1 ]]; }
hash_file() { sha256sum -- "$1" | awk '{print $1}'; }
sync_paths() { sync -f -- "$@"; }
failpoint() {
  if [[ $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AT:-} == "$1" ]]; then
    fail "injected $1 durability/transaction failure (isolated test only)"
  fi
}
# Preserve uncertain transactions and never replay them blindly. A prior
# durable COMMITTED journal may be retired only after verifying the recorded
# current installation identity under the exclusive maintenance gate.
shopt -s nullglob
recovery_dirs=("$bin_dir"/.stl-install.*)
shopt -u nullglob
for recovery in "${recovery_dirs[@]}"; do
  [[ -d $recovery && ! -L $recovery ]] || fail 'unsafe retained recovery identity'
  marker="$recovery/COMMITTED"
  is_regular "$marker" || fail 'unreconciled STL installer recovery directory exists; inspect it before retrying'
  saved_action=$(sed -n 's/^operation=//p' "$marker")
  saved_hash=$(sed -n 's/^sha256=//p' "$marker")
  [[ $saved_hash =~ ^[0-9a-f]{64}$ ]] || fail 'invalid committed recovery marker'
  [[ $saved_action == install || $saved_action == update || $saved_action == uninstall ]] || fail 'unknown committed recovery operation'
  # Journal v1 requires exactly three fields, in canonical order, with one
  # trailing newline. Incomplete/corrupt markers never authorize recovery.
  marker_body=$(cat -- "$marker") || fail 'cannot read committed recovery marker'
  marker_expected=$(printf 'status=committed\noperation=%s\nsha256=%s' "$saved_action" "$saved_hash")
  [[ $marker_body == "$marker_expected" && $(wc -c < "$marker") -eq $(( ${#marker_expected} + 1 )) ]] || fail 'invalid committed recovery journal structure'
  case "$saved_action" in
    install|update)
      is_regular "$record" && is_regular "$target" &&
        [[ -L $alias && $(readlink -- "$alias") == stl ]] &&
        [[ $(hash_file "$target") == "$saved_hash" ]] || fail 'committed installation differs; preserve recovery evidence'
      saved_record_version=$(sed -n 's/^version=//p' "$record")
      [[ $saved_record_version =~ ^(v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?|dev-[0-9a-f]{12})$ ]] || fail 'invalid committed recovery record version'
      record_body=$(cat -- "$record") || fail 'cannot read committed recovery record'
      record_expected=$(printf 'format=1\nproject=simple-tun-link\nversion=%s\nsha256=%s' "$saved_record_version" "$saved_hash")
      [[ $record_body == "$record_expected" && $(wc -c < "$record") -eq $(( ${#record_expected} + 1 )) ]] || fail 'committed recovery record identity is inconsistent'
      ;;
    uninstall)
      [[ ! -e $record && ! -L $record && ! -e $target && ! -L $target && ! -e $alias && ! -L $alias ]] || fail 'committed uninstall differs; preserve recovery evidence'
      ;;
    *) fail 'unknown committed recovery operation' ;;
  esac
  rm -rf -- "$recovery" || fail 'cannot retire verified committed recovery'
  sync_paths "$bin_dir" || fail 'cannot durably retire verified committed recovery'
done
read_record() {
  is_regular "$record" || fail 'STL ownership record is missing or not regular'
  grep -qx 'format=1' "$record" && grep -qx 'project=simple-tun-link' "$record" || fail 'invalid ownership record'
  prior_version=$(sed -n 's/^version=//p' "$record")
  prior_hash=$(sed -n 's/^sha256=//p' "$record")
  [[ $prior_hash =~ ^[0-9a-f]{64}$ && $prior_version =~ ^(v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?|dev-[0-9a-f]{12})$ ]] || fail 'invalid ownership record fields'
  is_regular "$target" || fail 'installed stl is missing or unsafe'
  [[ $(hash_file "$target") == "$prior_hash" ]] || fail 'installed stl differs from recorded owned binary; refusing overwrite'
  [[ -L $alias && $(readlink -- "$alias") == stl ]] || fail 'stlink alias missing or differs from installer-owned symlink'
  prior_record_hash=$(hash_file "$record")
}

if [[ $action == install ]]; then
  [[ ! -e $record && ! -L $record && ! -e $target && ! -L $target && ! -e $alias && ! -L $alias ]] || fail 'an installed or foreign STL identity already exists; refusing takeover'
else
  read_record
fi

# Only the existing installer-owned executable and record are admitted for
# post-install package provisioning; never change STL binary/Link State here.
# Runtime OS/package effects are not part of STL's binary rollback transaction.
if [[ $action == prepare ]]; then
  if [[ $expected_missing_supplied == 1 ]]; then
    expected_missing_pattern='^([a-z0-9-]+( [a-z0-9-]+)*)?$'
    [[ $expected_missing =~ $expected_missing_pattern ]] || fail 'untrusted expected missing package set'
  fi
  if [[ $expected_apt_plan_supplied == 1 ]]; then
    expected_apt_pattern='^([a-z0-9.+:-]+=[0-9a-zA-Z:.+~_-]+( [a-z0-9.+:-]+=[0-9a-zA-Z:.+~_-]+)*)?$'
    [[ $expected_apt_plan =~ $expected_apt_pattern ]] || fail 'untrusted expected APT dependency plan'
  fi
  ensure_packages
  printf '[OK] Selected backend packages prepared; kernel readiness and private IPsec service admission (if selected) still need independent verification. No STL executable or Link was changed.\n'
  exit 0
fi

# A release operation is not a Link lifecycle. Prevent uninstall unless STL's
# canonical read contract proves zero Links and the Engine-owned unit is absent.
if [[ $action == uninstall ]]; then
  # Installer holds exclusive maintenance flock. The canonical Go preflight
  # is the single authority on durable state and systemd enablement.
  checked=$("$target" maintenance pre-uninstall --json) || fail 'canonical uninstall preflight failed; no files removed'
  [[ $checked == '{"schema_version":1,"ready":true}' ]] || fail 'canonical uninstall preflight did not prove safety'

fi

stage=
record_tmp=
new_hash=
new_record_hash=
keep_recovery=0

# All failure compensation is identity-guarded. Keep previous recovery copies
# in stage (do not mv away the only copy) until the repaired canonical state
# and every applicable parent directory are durably synchronized.
finish() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ -n $stage && -d $stage ]]; then
    if (( rc == 0 )); then
      if [[ -f $stage/COMMITTED ]]; then
        # A deliberately retained, fsynced commit marker is reconciled and
        # retired by the next installer invocation, after verifying identity.
        :
      else
        rm -rf -- "$stage" || rc=1
        sync_paths "$bin_dir" || rc=1
      fi
    elif [[ -f $stage/COMMITTED ]]; then
      keep_recovery=1
    else
      if [[ $action == uninstall ]]; then
        if [[ ! -f $target || -L $target || $(hash_file "$target") != "$prior_hash" ]]; then
          if [[ ! -e $target && ! -L $target && -f $stage/previous-stl ]] &&
             [[ $(hash_file "$stage/previous-stl") == "$prior_hash" ]]; then
            cp -p -- "$stage/previous-stl" "$stage/recover-stl" &&
              sync_paths "$stage/recover-stl" "$stage" &&
              mv -T -- "$stage/recover-stl" "$target" || keep_recovery=1
          else
            keep_recovery=1
          fi
        fi
        if [[ ! -f $record || -L $record || $(hash_file "$record") != "$prior_record_hash" ]]; then
          if [[ ! -e $record && ! -L $record && -f $stage/previous-record ]] &&
             [[ $(hash_file "$stage/previous-record") == "$prior_record_hash" ]]; then
            cp -p -- "$stage/previous-record" "$record_dir/.stl-restore-record.$$" &&
              sync_paths "$record_dir/.stl-restore-record.$$" &&
              mv -T -- "$record_dir/.stl-restore-record.$$" "$record" || keep_recovery=1
          else
            keep_recovery=1
          fi
        fi
        if [[ ! -L $alias || $(readlink -- "$alias") != stl ]]; then
          if [[ ! -e $alias && ! -L $alias ]]; then
            ln -s stl "$alias" || keep_recovery=1
          else
            keep_recovery=1
          fi
        fi
      else
        if [[ -n $new_hash && -f $target && ! -L $target && $(hash_file "$target") == "$new_hash" ]]; then
          if [[ $action == update ]]; then
            if [[ $new_hash != "$prior_hash" ]]; then
              if [[ -f $stage/previous-stl && $(hash_file "$stage/previous-stl") == "$prior_hash" ]]; then
                cp -p -- "$stage/previous-stl" "$stage/recover-stl" &&
                  sync_paths "$stage/recover-stl" "$stage" &&
                  mv -T -- "$stage/recover-stl" "$target" || keep_recovery=1
              else
                keep_recovery=1
              fi
            fi
          else
            rm -- "$target" || keep_recovery=1
          fi
        elif [[ $action == install && ( -e $target || -L $target ) ]]; then
          keep_recovery=1
        elif [[ $action == update ]] &&
             [[ ! -f $target || -L $target || $(hash_file "$target") != "$prior_hash" ]]; then
          keep_recovery=1
        fi
        if [[ $action == install && -L $alias && $(readlink -- "$alias") == stl ]]; then
          rm -- "$alias" || keep_recovery=1
        elif [[ $action == install && ( -e $alias || -L $alias ) ]]; then
          keep_recovery=1
        fi
        if [[ -n $new_record_hash && -f $record && ! -L $record && $(hash_file "$record") == "$new_record_hash" ]]; then
          if [[ $action == update ]]; then
            if [[ -f $stage/previous-record && $(hash_file "$stage/previous-record") == "$prior_record_hash" ]]; then
              cp -p -- "$stage/previous-record" "$record_dir/.stl-restore-record.$$" &&
                sync_paths "$record_dir/.stl-restore-record.$$" &&
                mv -T -- "$record_dir/.stl-restore-record.$$" "$record" || keep_recovery=1
            else
              keep_recovery=1
            fi
          else
            rm -- "$record" || keep_recovery=1
          fi
        elif [[ $action == install && ( -e $record || -L $record ) ]]; then
          keep_recovery=1
        elif [[ $action == update ]] &&
             [[ ! -f $record || -L $record || $(hash_file "$record") != "$prior_record_hash" ]]; then
          keep_recovery=1
        fi
      fi
      # A successful apparent compensation is not a proven rollback until
      # all restored files, aliases and directory entries have been fsynced.
      if (( !keep_recovery )); then
        [[ ! -e $target || ( -f $target && ! -L $target ) ]] || keep_recovery=1
        if [[ -f $target ]]; then sync_paths "$target" || keep_recovery=1; fi
        if [[ -f $record ]]; then sync_paths "$record" || keep_recovery=1; fi
        sync_paths "$bin_dir" "$record_dir" "$stage" || keep_recovery=1
        if [[ $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AT:-} == compensation-sync ]]; then
          keep_recovery=1
        fi
      fi
      if (( !keep_recovery )); then
        rm -rf -- "$stage" || keep_recovery=1
        sync_paths "$bin_dir" || keep_recovery=1
      fi
    fi
    if (( keep_recovery )); then
      printf 'stl installer [FAILED]: partial failure; inspect retained recovery directory: %s\n' "$stage" >&2
    fi
  fi
  if [[ -n $record_tmp ]]; then
    rm -f -- "$record_tmp" "$record_tmp.recover"
  fi
  exit "$rc"
}

# All source and record materials must be synced before the first canonical
# namespace mutation. COMMITTED is written only after both identities are
# verified and all canonical publication/directory syncs succeeded.
commit_marker() {
  local committed_hash=$1
  printf 'status=committed\noperation=%s\nsha256=%s\n' "$action" "$committed_hash" > "$stage/COMMITTED"
  chmod 0600 "$stage/COMMITTED"
  sync_paths "$stage/COMMITTED" "$stage" "$bin_dir" "$record_dir" || fail 'cannot durably publish committed transaction marker'
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage=$(mktemp -d "$bin_dir/.stl-install.XXXXXXXX")

if [[ $action == uninstall ]]; then
  cp -p -- "$target" "$stage/previous-stl"
  cp -p -- "$record" "$stage/previous-record"
  [[ $(hash_file "$target") == "$prior_hash" && $(hash_file "$record") == "$prior_record_hash" ]] || fail 'installed identity changed before uninstall'
  sync_paths "$stage/previous-stl" "$stage/previous-record" "$stage" "$bin_dir" || fail 'cannot durably preserve uninstall rollback source'
  failpoint prepublish-sync
  rm -- "$alias"
  sync_paths "$bin_dir" || fail 'cannot durably retire alias'
  # The durable previous-stl is a copy, not a hardlink. Unlink canonical
  # instead of moving its live inode into recovery: queued processes must see
  # /usr/local/bin/stl (deleted) after uninstall, not a recovery pathname.
  rm -- "$target"
  sync_paths "$bin_dir" "$stage" || fail 'cannot durably retire canonical executable'
  rm -- "$record"
  if [[ $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AFTER_UNINSTALL_REMOVE:-} == 1 ]]; then
    fail 'injected uninstall failure (isolated test only)'
  fi
  sync_paths "$record_dir" || fail 'cannot durably retire ownership record'
  failpoint record-sync
  [[ ! -e $target && ! -L $target && ! -e $alias && ! -L $alias && ! -e $record && ! -L $record ]] || fail 'uninstall identities not fully retired'
  commit_marker "$prior_hash"
  printf '[OK] Uninstalled installer-owned stl/stlink only; Link state was left untouched.\n'
  exit 0
fi

arch=$(uname -m)
case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) fail "unsupported architecture: $arch" ;; esac
if [[ -n $bundle ]]; then
  [[ -d $bundle && ! -L $bundle ]] || fail 'bundle must be a directory, not a symlink'
  bundle=$(realpath -e -- "$bundle")
  is_regular "$bundle/BUILD-MANIFEST.txt" || fail 'bundle manifest missing or unsafe'
  version=$(sed -n 's/^version=//p' "$bundle/BUILD-MANIFEST.txt")
  [[ $version =~ ^(v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?|dev-[0-9a-f]{12})$ ]] || fail 'invalid bundle version'
fi
asset="stl_${version}_linux_${arch}"
for file in SHA256SUMS BUILD-MANIFEST.txt LICENSE "$asset"; do
  if [[ -n $bundle ]]; then
    is_regular "$bundle/$file" || fail "bundle file missing or unsafe: $file"
    cp -- "$bundle/$file" "$stage/$file" || fail "cannot read bundle file: $file"
  else
    url="https://github.com/ach1992/simple-tun-link/releases/download/${version}/${file}"
    curl -fLSs --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 2 -o "$stage/$file" "$url" || fail "cannot download release file: $file"
  fi
done
for file in BUILD-MANIFEST.txt LICENSE "$asset"; do
  expected=$(awk -v name="$file" '$2 == name {print $1}' "$stage/SHA256SUMS")
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || fail "missing/duplicate or malformed SHA256 entry for $file"
  [[ $(hash_file "$stage/$file") == "$expected" ]] || fail "checksum mismatch for $file"
done
manifest="$stage/BUILD-MANIFEST.txt"
grep -qx 'project=simple-tun-link' "$manifest" && grep -qx 'executable=stl' "$manifest" && grep -qx 'license=MIT' "$manifest" && grep -qx "version=$version" "$manifest" || fail 'release manifest does not describe the intended STL build'
if [[ -z $bundle ]]; then grep -qx 'mode=tag' "$manifest" || fail 'remote release must be built from a tag'; fi
commit=$(sed -n 's/^commit=//p' "$manifest")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail 'invalid release commit metadata'
[[ $(head -n 1 "$stage/LICENSE") == 'MIT License' ]] || fail 'release LICENSE is not MIT'
install -m 0755 -- "$stage/$asset" "$stage/incoming"
metadata=$("$stage/incoming" version --json) || fail 'downloaded binary cannot report version metadata'
[[ $metadata == *\"version\":\"$version\"* && $metadata == *\"commit\":\"$commit\"* ]] || fail 'release executable and manifest identity disagree'
# Install only missing distro-native prerequisites, after authenticating the
# exact candidate artifact and BEFORE touching the canonical STL executable.
# Package installations are not part of the STL binary rollback transaction;
# do not auto-remove/undo administrator-owned APT state on any failure.
if [[ $prefix == /usr/local ]]; then ensure_packages; fi
new_hash=$(hash_file "$stage/incoming")
record_tmp=$(mktemp "$record_dir/.install-record.XXXXXXXX")
printf 'format=1\nproject=simple-tun-link\nversion=%s\nsha256=%s\n' "$version" "$new_hash" > "$record_tmp"
chmod 0600 "$record_tmp"
new_record_hash=$(hash_file "$record_tmp")
# The incoming executable and prepared metadata must be durable before the
# first destructive rename. A directory sync records the recovery namespace.
sync_paths "$stage/incoming" "$record_tmp" "$stage" "$record_dir" "$bin_dir" || fail 'cannot durably prepare incoming install transaction'

if [[ $action == update ]]; then
  cp -p -- "$target" "$stage/previous-stl"
  cp -p -- "$record" "$stage/previous-record"
  [[ $(hash_file "$target") == "$prior_hash" && $(hash_file "$record") == "$prior_record_hash" ]] || fail 'installed binary or record changed before update'
  sync_paths "$stage/previous-stl" "$stage/previous-record" "$stage" "$bin_dir" || fail 'cannot durably preserve update rollback sources'
  if [[ $prior_hash == "$new_hash" ]]; then
    printf '[INFO] stl is already installed from this exact artifact (%s).\n' "$version"
    exit 0
  fi
fi
failpoint prepublish-sync
# Incoming and canonical executable are in the same directory/filesystem.
# mv -T is an atomic rename: the old executable is never truncated in place.
mv -T -- "$stage/incoming" "$target"
if [[ -n $bundle && $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AFTER_SWAP:-} == 1 ]]; then
  fail 'injected after-swap failure (offline isolated test only)'
fi
if [[ $action == update && -n $bundle && $prefix != /usr/local && ${STL_INSTALL_TEST_CORRUPT_BACKUP:-} == 1 ]]; then
  printf 'damaged\n' >> "$stage/previous-stl"
  fail 'injected damaged recovery source (offline isolated test only)'
fi
sync_paths "$target" "$bin_dir" || fail 'binary publication sync failed'
failpoint post-executable-sync
if [[ $action == install ]]; then
  ln -s stl "$alias"
  sync_paths "$bin_dir" || fail 'alias publication sync failed'
fi
if [[ $action == update ]]; then
  [[ $(hash_file "$record") == "$prior_record_hash" ]] || fail 'install record changed during binary update; reconciliation required'
else
  [[ ! -e $record && ! -L $record ]] || fail 'install record appeared during installation; refusing overwrite'
fi
mv -T -- "$record_tmp" "$record"
sync_paths "$record" "$record_dir" || fail 'ownership record publication sync failed'
failpoint record-sync
[[ $(hash_file "$record") == "$new_record_hash" && $(hash_file "$target") == "$new_hash" && -L $alias && $(readlink -- "$alias") == stl ]] || fail 'post-publication identity check failed'
commit_marker "$new_hash"
printf '[OK] %s stl %s for linux/%s; stlink resolves to the same executable.\n' "${action^}" "$version" "$arch"

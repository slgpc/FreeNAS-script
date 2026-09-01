#Please donate project:
#
#Paypal SLGPC.sec@gmail.com
#
#Crypto Wallet SuperTrump: 0x25E99A4b58C83dC85c4668f43695eb00a4AB6a46 
#Trump Official: 2ZUw5ytdtRuTj9EhnJ6i7xErEo2cwHhbBTCAF9Wuwx9g 
#USDT Erc20: 0x25E99A4b58C83dC85c4668f43695eb00a4AB6a46 
#Bitcoin: bc1qnjypme6cxn9d2nhqyyc3mdun0lm8m6m6982mqu
#
#!/bin/sh
#
# update_av_tools.sh
# ---------------------------------------------------------------------------
# Downloads a set of portable antivirus scanners via curl (with retries
# and resuming downloads in case of unstable internet connection) to a dataset shared
# via SMB as \\192.168.0.100\anti\, and after each successful download:
# - sets permissions to 555 (read and execute, no write)
# - sets the FreeBSD "user immutable" flag (chflags uchg), which prevents
# the file from being deleted or modified from the client (Windows/Mac), including
# ransomware—only root on the NAS can remove the flag.
#
# Run on TrueNAS CORE / FreeNAS (FreeBSD) as root,
# for example, via System -> Advanced -> Cron Jobs.
#
# IMPORTANT:
# 1. The list below is not a complete list from virustotal.txt: there are ~70 names of
# VirusTotal scanning engines, most of which do not have separate
# distributed portable/CLI utilities (these are engines inside other
# products). Below are only those that actually have a freely
# downloadable portable scanner.
# 2. Some vendors (Dr.Web, Sophos, McAfee/Trellix Stinger) have links to
# the file that "float" over time (dynamic name, email/EULA requirement
# on the page) - such items below are marked with TODO and commented out.
# They should be manually checked once and the current URL entered.
# 3. If you are under US jurisdiction, consider the export restrictions on Kaspersky software (effective from 2024) and decide for yourself whether KVRT is necessary.
# ---------------------------------------------------------------------------

set -u

# ======================= SETTINGS =======================================

# A dataset directory that is shared as \\192.168.0.100\anti\
DEST_DIR="/mnt/tank/anti"

# Where to write the log
LOG_DIR="/mnt/tank/anti/.logs"
LOG_FILE="${LOG_DIR}/update_av_tools.log"

# A lock file to prevent two cron runs from intersecting.
LOCK_FILE="/var/run/update_av_tools.lock"

# Curl parameters for unstable internet access
CURL_OPTS="--fail --location --silent --show-error \
  --connect-timeout 15 \
  --retry 10 --retry-delay 5 --retry-max-time 600 --retry-connrefused \
  --continue-at -"

# Share file owner/group (adjust for your SMB user)
FILE_OWNER="root:wheel"

# ======================= TABLE OF UTILITIES===================================
# Single-line format: "Name|URL|Output_file_name|SHA256(optional, can be empty)"
# Empty checksum = verification is skipped (there is simply no verified
# current hash at the moment; enter your own if you have one).

AV_LIST="

Kaspersky_KVRT|https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe|KVRT.exe|
Microsoft_Safety_Scanner_x64|https://go.microsoft.com/fwlink/?LinkId=212732|msert_x64.exe|
Microsoft_Safety_Scanner_x86|https://go.microsoft.com/fwlink/?LinkId=212733|msert_x86.exe|
AVG_clear|https://honzik.avcdn.net/setup/avg-av/release/avg_av_clear.exe?ref=gdid_5760123c-bab0-4a94-bd17-1cc5f96fab57&alt=ru-ru|avg_av_clear.exe|
Comodo_Cleaning_Essentials|http://download.comodo.com/cce/download/setups/|cce_2.5.242177.201_x32.zip|
AdwCleaner|https://adwcleaner.malwarebytes.com/adwcleaner?channel=release|adwcleaner.exe
Malwarebytes|https://downloads.malwarebytes.com/file/mb-windows?filename=MBSetup-8.8.exe&t=1788243935751|MBSetup-8.8.exe|
SUPERAntiSpyware_Free_Edition|https://secure.superantispyware.com/SUPERAntiSpyware.exe|SUPERAntiSpyware.exe|
Emsisoft_Emergency_Kit|https://dl.emsisoft.com/EmsisoftEmergencyKit.exe|EmsisoftEmergencyKit.exe|
Stinger32|https://downloadcenter.trellix.com/products/mcafee-avert/stinger/stinger32.exe|stinger32.exe|
Stinger64|https://downloadcenter.trellix.com/products/mcafee-avert/stinger/stinger64.exe|stinger64.exe|
HouseCall|https://api.link.trendmicro.com/events/landing-page?product_id=9cdd2&source=TMpt&platform=windows|HousecallLauncher64.exe|
ClamAVx64|https://oss.netfarm.it/clamav/files/clamav-1.5.2-x64.7z|clamav-1.5.2-x64.7z|
ClamAVx86|https://oss.netfarm.it/clamav/files/clamav-1.5.2-legacy-x86.7z|clamav-1.5.2-legacy-x86.7z
ClamAVwin9x|https://oss.netfarm.it/clamav/files/clamav-1.4.4-legacy-win9x.7z|clamav-1.4.4-legacy-win9x.7z|
Panda_Cloud_Cleaner|https://repository.pandasecurity.com/pandacloudcleaner/rescuedisk/PandaCloudCleanerUSB.exe|PandaCloudCleanerUSB.exe|
"

# --- Blanks for the rest (uncomment and enter the verified URL) ---
# TODO: Dr.Web CureIt — URL with a random hash in the file name, found from
# the page https://free.drweb.com/cureit/ (curl -sI via redirect).
# Drweb_CureIt|https://download.geo.drweb.com/pub/drweb/cureit/drweb-cureit.exe|drweb-cureit.exe|
#
# TODO: Sophos Scan & Clean - check the current link
#       https://www.sophos.com/en-us/free-tools/virus-removal-tool
# Sophos_ScanAndClean|<URL>|sophos_scan_and_clean.exe|
#
# TODO: McAfee/Trellix Stinger - check for
#       https://www.trellix.com/downloads/free-tools/stinger/
# Trellix_Stinger_x64|<URL>|stinger64.exe|
#
# 
# TODO: Emsisoft Emergency Kit (portable, also available for Linux)
#Emsisoft_EmergencyKit|https://dl.emsisoft.com/EmsisoftEmergencyKit.zip|EmsisoftEmergencyKit.zip|

# ======================= SERVICE FUNCTIONS ================================

log() {
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] $1" | tee -a "$LOG_FILE"
}

# Remove the immutable flag (if present) without failing with an error if it was not present.
unlock_file() {
  f="$1"
  [ -e "$f" ] && chflags nouchg "$f" 2>/dev/null
}

# Assign final permissions: read+execute for everyone, no write, + immutable
lock_file_down() {
  f="$1"
  chown "$FILE_OWNER" "$f" 2>/dev/null
  chmod 555 "$f"          # r-xr-xr-x 
  chflags uchg "$f"       # prohibition of deletion/modification (removed by root)
}

# Downloading a single utility with backups and download resuming
download_one() {
  name="$1"; url="$2"; outfile="$3"; sha256="$4"
  tmp="${DEST_DIR}/.tmp_${outfile}"
  dest="${DEST_DIR}/${outfile}"

  log "=== ${name}: starting download ==="

  # If a temporary file remains from a previous interruption, curl -C will finish downloading it.
  attempt=1
  max_attempts=3
  ok=0

  while [ "$attempt" -le "$max_attempts" ]; do
    log "${name}: try ${attempt}/${max_attempts}"
    # shellcheck disable=SC2086
    if curl $CURL_OPTS -o "$tmp" "$url"; then
      ok=1
      break
    else
      rc=$?
      log "${name}: curl failed with error (code ${rc}), waiting before trying again"
      sleep 10
    fi
    attempt=$((attempt + 1))
  done

  if [ "$ok" -ne 1 ]; then
    log "${name}: FAILED to download after ${max_attempts} attempts - skipping"
    return 1
  fi

  # Checksum verification if specified
  if [ -n "$sha256" ]; then
    got="$(sha256 -q "$tmp" 2>/dev/null || sha256sum "$tmp" | awk '{print $1}')"
    if [ "$got" != "$sha256" ]; then
      log "${name}: SHA256 NOT EQUAL (wait $sha256, got $got) — file restricted"
      rm -f "$tmp"
      return 1
    fi
    log "${name}: control sum ok"
  fi

  # Remove immutable from the old version (if any), replace it, and re-lock it.
  unlock_file "$dest"
  mv -f "$tmp" "$dest"
  lock_file_down "$dest"

  log "${name}: OK -> ${dest}"
  return 0
}

# ======================= MAIN MOVEMENT======================================

# Lock from parallel launch
if [ -e "$LOCK_FILE" ] && kill -0 "$(cat "$LOCK_FILE" 2>/dev/null)" 2>/dev/null; then
  echo "Another instance of the script is already running, exiting."
  exit 1
fi
echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

mkdir -p "$DEST_DIR" "$LOG_DIR"

log "##########Launching an update of antivirus utilities##########"

fail_count=0
ok_count=0

LIST_TMP="$(mktemp)"
echo "$AV_LIST" > "$LIST_TMP"

#We read from a file (not a pipe) so that the while loop isn't executed in a subshell —
# otherwise, the ok_count/fail_count counters won't be saved after the loop
while IFS='|' read -r name url outfile sha256; do
  #skip empty/commented lines
  [ -We read from a file (not a pipe) so that the while loop isn't executed in a subshell —
# otherwise, the ok_count/fail_count counters won't be saved after the loopz "$name" ] && continue

  if download_one "$name" "$url" "$outfile" "$sha256"; then
    ok_count=$((ok_count + 1))
  else
    fail_count=$((fail_count + 1))
  fi
done < "$LIST_TMP"

rm -f "$LIST_TMP"

log "########## Ready. Successful: ${ok_count}, with fail: ${fail_count} ##########"
log "Directory: ${DEST_DIR}"

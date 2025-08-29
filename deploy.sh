#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# TurnKey LAMP one‑shot setup — v2.16
# - FIX (dev): Apache served /var/www/html -> 403/AH01276. We now **rewrite** the
#   dev vhost with the correct DocumentRoot and a matching <Directory>, removing
#   the stale /var/www/html block that used to win. Also sets DirectoryIndex.
# - PREV: v2.15 dev ACLs for www-data; v2.14 fstab/mount noise fix; portable cfg;
#         data‑disk flow; cloudflared repo keyring + static fallback; prod deploy
# - No sudo; run as root. Idempotent. Stores answers for reuse.
# =============================================================

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
say(){ echo -e "\e[1;32m$*\e[0m"; }
warn(){ echo -e "\e[33m$*\e[0m" >&2; }
err(){ echo -e "\e[31m$*\e[0m" >&2; }
prompt(){ local q="$1" d="${2-}" a; if [[ -n "$d" ]]; then read -rp "$q [$d]: " a || true; echo "${a:-$d}"; else read -rp "$q: " a || true; echo "$a"; fi; }
yn(){ local def="${1:-yes}"; local q="$2"; local a; a=$(prompt "$q (yes/no)" "$def"); a=${a,,}; [[ "$a" == y || "$a" == yes ]]; }

have_pkg(){ local p="${1-}"; [[ -n "$p" ]] || return 1; local c; c=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/{print $2}'); [[ -n "$c" && "$c" != "(none)" ]]; }
apt_install(){ local to=() sk=(); for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 && continue; have_pkg "$p" && to+=("$p") || sk+=("$p"); done; if ((${#to[@]})); then apt-get update -yq; apt-get install -yq --no-install-recommends "${to[@]}"; fi; ((${#sk[@]})) && warn "[info] Skipping unavailable: ${sk[*]}" || true; }

as_user(){ local u="${1:?missing user}"; shift || true; runuser -u "$u" -- bash -lc "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

# ---- Paths & portable config ----
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" &>/dev/null && pwd -P)"
CONFIG_FILE_DEFAULT="${SCRIPT_DIR}/setup.options.env"
CONFIG_FILE="${CONFIG_FILE:-$CONFIG_FILE_DEFAULT}"

# ---- Load saved selections ----
DEFAULTS_DIR="/etc/tkl-setup"; DEFAULTS_FILE="${DEFAULTS_DIR}/defaults.env"
set +u
[[ -f "$CONFIG_FILE" ]] && . "$CONFIG_FILE"
[[ -f "$DEFAULTS_FILE" ]] && . "$DEFAULTS_FILE"
set -u

# ---- Base packages ----
apt_install ca-certificates curl git unzip jq acl apache2 php php-cli php-curl php-sqlite3 php-mbstring php-gd libapache2-mod-php php-zip php-xml php-intl rsync parted e2fsprogs gnupg

# Composer
if ! command -v composer >/dev/null 2>&1; then
  php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
  php composer-setup.php --install-dir=/usr/local/bin --filename=composer
  rm -f composer-setup.php
fi

# ---------------- Inputs ----------------
MODE_INPUT=$(prompt "Is this a production or dev machine? (production/dev)" "${MODE:-production}"); MODE=${MODE_INPUT,,}
FQDN=$(prompt "Enter the FQDN for this host (e.g. app.example.org)" "${FQDN:-}")
GH_USER=$(prompt "GitHub user or org name (e.g. my-org)" "${GH_USER:-}")
GH_REPO=$(prompt "GitHub repo name (e.g. my-app)" "${GH_REPO:-}")
DEFAULT_BRANCH=$(prompt "Default branch for dev (ignored for production)" "${DEFAULT_BRANCH:-main}")
TAG_PATTERN=$(prompt "Production: tag pattern to match (glob)" "${TAG_PATTERN:-v*}")
WRITABLE_DIRS=$(prompt "Writable directories (space-separated, relative to project root)" "${WRITABLE_DIRS:-uploads storage cache logs sessions}")
GIT_NAME=$(prompt "[dev] Git author.name" "${GIT_NAME:-$GH_USER}")
GIT_EMAIL=$(prompt "[dev] Git author.email" "${GIT_EMAIL:-dev@${FQDN}}")

DATA_ROOT_DEFAULT="${DATA_ROOT:-/srv/${FQDN}}"
DATA_ROOT=$(prompt "Data root (shared runtime data & SQLite)" "$DATA_ROOT_DEFAULT")
DATA_DEV=$(prompt "(Optional) Block device to use for data (disk or partition, e.g. /dev/sdb or /dev/sdb1)" "${DATA_DEV:-}")
EXISTING_DATA=$(prompt "(Optional) Existing data source to mount (device /dev/… or directory to bind onto DATA_ROOT)" "${EXISTING_DATA:-}")

CODE_PATH="${CODE_PATH:-/code}"
SITE_ROOT="/var/www/${FQDN}"; RELEASES_DIR="${SITE_ROOT}/releases"; CURRENT_LINK="${SITE_ROOT}/current"; WORKTREE="${SITE_ROOT}/app"
SHARED_DIR="${DATA_ROOT}/shared"; SQLITE_DIR="${DATA_ROOT}/sqlite"; HOOKS_DIR="/opt/${FQDN}/hooks"; ETC_SITE="/etc/${FQDN}"

mkdir -p "$RELEASES_DIR" "$HOOKS_DIR" "$ETC_SITE" "$DEFAULTS_DIR" "$SITE_ROOT"

# ---- Persist selections to portable + system files ----
write_cfg(){ local file="$1"; umask 0077; cat > "$file" <<EOF
# Saved by TurnKey LAMP one‑shot on $(date -u +'%F %T UTC')
MODE="$MODE"
FQDN="$FQDN"
GH_USER="$GH_USER"
GH_REPO="$GH_REPO"
DEFAULT_BRANCH="$DEFAULT_BRANCH"
TAG_PATTERN="$TAG_PATTERN"
WRITABLE_DIRS="$WRITABLE_DIRS"
GIT_NAME="$GIT_NAME"
GIT_EMAIL="$GIT_EMAIL"
DATA_ROOT="$DATA_ROOT"
CODE_PATH="$CODE_PATH"
EXISTING_DATA="$EXISTING_DATA"
DATA_DEV="$DATA_DEV"
EOF
}
write_cfg "$CONFIG_FILE"; write_cfg "$DEFAULTS_FILE"

# ---------------- Storage helpers (unchanged from v2.15) ----------------
slugify_label(){ local s="DATA_${FQDN}"; s=$(echo "$s" | tr -c 'A-Za-z0-9_-' '_'); echo "${s:0:16}"; }
lsblk_json(){ lsblk -J -o NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINT,PKNAME >/tmp/lsblk.json; }
first_child_part(){ local dev="$1"; jq -r --arg p "$dev" '.blockdevices[] | select(.path==$p) | .children[]? | select(.type=="part") | .path' /tmp/lsblk.json | head -n1; }
is_whole_disk(){ local dev="$1"; jq -e --arg p "$dev" '.blockdevices[] | select(.path==$p and .type=="disk")' /tmp/lsblk.json >/dev/null; }
mounted_where(){ local dev="$1"; jq -r --arg p "$dev" '.blockdevices[] as $b | ([$b] + ($b.children//[]))[] | select(.path==$p) | .mountpoint // ""' /tmp/lsblk.json; }
wait_for_udev(){ udevadm settle -t 5 || true; partprobe >/dev/null 2>&1 || true; sleep 1; lsblk_json; }
wait_for_path(){ local p="$1"; for i in {1..20}; do [[ -e "$p" ]] && return 0; udevadm settle -t 2 || true; sleep 0.25; done; return 1; }
mk_single_part(){ local disk="$1"; warn "[disk] Creating GPT and single ext4 partition on $disk"; parted -s "$disk" mklabel gpt mkpart primary ext4 1MiB 100% >/dev/null; wait_for_udev; local child; child=$(first_child_part "$disk" || true); if [[ -n "$child" ]]; then wait_for_path "$child" || true; echo -n "$child"; else echo -n ""; fi }
fmt_ext4(){ local node="$1"; local label="$2"; warn "[fmt] mkfs.ext4 on $node (label=$label)"; wipefs -fa "$node" >/dev/null 2>&1 || true; mkfs.ext4 -F -L "$label" "$node" >/dev/null; }

fstab_add_line(){ local line="$1"; if ! grep -qsF -- "$line" /etc/fstab; then echo "$line" >> /etc/fstab; systemctl daemon-reload || true; fi }
add_fstab_and_mount(){ local node="$1" mnt="$2" opts="noatime,nodiratime" uuid fstype line; uuid=$(blkid -s UUID -o value "$node" 2>/dev/null || true); [[ -z "$uuid" ]] && { err "No UUID found for $node"; return 1; }; fstype=$(blkid -s TYPE -o value "$node" 2>/dev/null || echo ext4); mkdir -p "$mnt"; line="UUID=$uuid  $mnt  $fstype  $opts  0  2"; fstab_add_line "$line"; mountpoint -q "$mnt" || mount -U "$uuid" "$mnt" || mount "$node" "$mnt" || true; }
maybe_migrate(){ local target="$1" stagedir="$2"; [[ -d "$stagedir" ]] || return 0; if [[ -n $(find "$stagedir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) ]]; then if yn yes "Copy existing data from prior $DATA_ROOT into the new volume?"; then say "> Migrating prior data into $target ..."; rsync -aHAX "$stagedir"/ "$target"/ || rsync -a "$stagedir"/ "$target"/; say "> Migration complete."; fi; fi; rm -rf "$stagedir" || true; }

# ---------------- Data volume (existing or new) ----------------
install -d -m 755 "$DATA_ROOT"
had_local=0; stage=""
if ! mountpoint -q "$DATA_ROOT" && [[ -n $(find "$DATA_ROOT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) ]]; then had_local=1; stage=$(mktemp -d); say "Staging current contents of $DATA_ROOT before mounting"; rsync -a "$DATA_ROOT"/ "$stage"/; fi

if [[ -n "$EXISTING_DATA" && -d "$EXISTING_DATA" && ! -b "$EXISTING_DATA" ]]; then
  mountpoint -q "$DATA_ROOT" || mount --bind "$EXISTING_DATA" "$DATA_ROOT"
  fstab_add_line "$EXISTING_DATA $DATA_ROOT none bind 0 0"
  maybe_migrate "$DATA_ROOT" "$stage"
else
  node=""; disk=""; lsblk_json
  if [[ -n "${EXISTING_DATA:-}" && -e "${EXISTING_DATA}" ]]; then node="$EXISTING_DATA"; elif [[ -n "${DATA_DEV:-}" && -e "${DATA_DEV}" ]]; then node="$DATA_DEV"; fi
  if [[ -n "$node" ]]; then
    if is_whole_disk "$node"; then disk="$node"; child=$(first_child_part "$disk" || true); if [[ -z "$child" ]]; then say "Detected whole disk with no partitions: $disk"; if yn yes "Create a single partition and format it?"; then child=$(mk_single_part "$disk"); else child="$disk"; fi; fi; node="$child"; fi
    mp=$(mounted_where "$node"); if [[ -n "$mp" && "$mp" != "null" ]]; then if yn yes "Device $node is mounted at $mp. Unmount to proceed?"; then umount "$node" || umount "$mp" || true; wait_for_udev; fi; fi
    fstype=$(blkid -s TYPE -o value "$node" 2>/dev/null || true); label=$(slugify_label)
    if [[ -n "$fstype" ]]; then say "Found filesystem on $node (type=$fstype)."; if yn yes "Use existing data and mount without formatting?"; then add_fstab_and_mount "$node" "$DATA_ROOT"; else echo; err "*** WARNING: Will FORMAT $node as ext4 and ERASE existing data ***"; read -rp "Confirm by typing FORMAT: " C || true; if [[ "$C" == "FORMAT" ]]; then fmt_ext4 "$node" "$label"; add_fstab_and_mount "$node" "$DATA_ROOT"; else warn "Format cancelled. Using existing filesystem if mountable."; add_fstab_and_mount "$node" "$DATA_ROOT"; fi; fi
    else say "No filesystem detected on $node."; if yn yes "Format as ext4 and use it for $DATA_ROOT?"; then fmt_ext4 "$node" "$label"; add_fstab_and_mount "$node" "$DATA_ROOT"; else warn "No filesystem created; continuing without a mounted data volume."; fi; fi
    if (( had_local )) && mountpoint -q "$DATA_ROOT"; then maybe_migrate "$DATA_ROOT" "$stage"; else rm -rf "$stage" >/dev/null 2>&1 || true; fi
  else warn "No data device provided. Using existing filesystem at $DATA_ROOT."; fi
fi

# Ensure expected subdirs exist and are writable by www-data
install -d -m 750 -o www-data -g www-data "$SQLITE_DIR" "$SHARED_DIR"
setfacl -R -m g:www-data:rwX "$SQLITE_DIR" "$SHARED_DIR" || true
setfacl -dR -m g:www-data:rwX "$SQLITE_DIR" "$SHARED_DIR" || true

# Move any *.db to SQLITE_DIR
shopt -s nullglob; for db in *.db; do say "+ Moving $db -> $SQLITE_DIR/"; mv -f "$db" "$SQLITE_DIR/"; done; shopt -u nullglob
chown -R www-data:www-data "$SQLITE_DIR"; chmod -R 750 "$SQLITE_DIR"

# ---------------- Apache base vhost ----------------
mkdir -p /etc/apache2/conf-available
printf 'ServerName %s\n' "$FQDN" > "/etc/apache2/conf-available/servername-${FQDN}.conf"
a2enconf "servername-${FQDN}" >/dev/null || true

a2enmod proxy proxy_http proxy_wstunnel headers rewrite alias remoteip dir >/dev/null || true

VHOST_CONF="/etc/apache2/sites-available/${FQDN}.conf"
{
  echo "<VirtualHost *:80>"; echo "  ServerName $FQDN"; echo "  ServerAdmin webmaster@localhost"; echo ""; echo "  DocumentRoot /var/www/html"; echo "  <Directory /var/www/>"; echo "    AllowOverride All"; echo "    Require all granted"; echo "    Options FollowSymLinks"; echo "  </Directory>"; echo ""; echo "  ProxyPreserveHost On"; echo "  RewriteEngine On"; echo "  RewriteCond %{HTTP:Upgrade} =websocket [NC]"; printf '  RewriteRule ^%s/(.*)$ ws://127.0.0.1:8080/\$1 [P,L]\n' "$CODE_PATH"; echo "  RewriteCond %{HTTP:Upgrade} !=websocket [NC]"; printf '  RewriteRule ^%s/(.*)$ http://127.0.0.1:8080/\$1 [P,L]\n' "$CODE_PATH"; printf '  ProxyPassReverse %s/ http://127.0.0.1:8080/\n' "$CODE_PATH"; echo ""; echo "  Alias /hooks/github ${HOOKS_DIR}/github-webhook.php"; echo "  <Directory ${HOOKS_DIR}>"; echo "    Require all granted"; echo "    Options FollowSymLinks"; echo "  </Directory>"; echo ""; echo "  RemoteIPHeader CF-Connecting-IP"; echo "  RemoteIPTrustedProxy 127.0.0.1"; echo "  ErrorLog /var/log/apache2/${FQDN}-error.log"; echo "  CustomLog /var/log/apache2/${FQDN}-access.log combined"; echo "</VirtualHost>"
} > "$VHOST_CONF"

a2dissite 000-default >/dev/null 2>&1 || true
a2ensite "$FQDN" >/dev/null
apachectl configtest && systemctl reload apache2 || true

# ---------------- Cloudflared (Tunnel) ----------------
install_cloudflared(){
  command -v cloudflared >/dev/null 2>&1 && return 0
  say "+ Installing cloudflared"
  local KEYRING="/usr/share/keyrings/cloudflare-main.gpg" LIST="/etc/apt/sources.list.d/cloudflared.list"
  rm -f "$LIST" || true; mkdir -p "$(dirname "$KEYRING")"
  if curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --dearmor -o "$KEYRING" 2>/dev/null; then
    chmod 644 "$KEYRING"; . /etc/os-release; local CODENAME="${VERSION_CODENAME:-bookworm}"
    echo "deb [signed-by=$KEYRING] https://pkg.cloudflare.com/cloudflared ${CODENAME} main" > "$LIST"
    if apt-get update -yq && apt-get install -yq cloudflared; then return 0; fi
    warn "APT install of cloudflared failed; falling back to static binary."
  else warn "Could not import Cloudflare GPG key; falling back to static binary."; fi
  local arch url; arch=$(dpkg --print-architecture)
  case "$arch" in amd64) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" ;; arm64) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" ;; armhf|arm) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm" ;; *) err "Unsupported architecture for cloudflared static binary: $arch"; return 1 ;; esac
  if curl -fL "$url" -o /usr/local/bin/cloudflared; then chmod +x /usr/local/bin/cloudflared; return 0; fi; return 1
}

if ! install_cloudflared; then err "Failed to install cloudflared (both apt and static fallback). You can proceed without a tunnel."; else
  TUNNEL_NAME="tkl-${FQDN}"; cloudflared tunnel list 2>/dev/null | awk '{print $2}' | grep -qx "$TUNNEL_NAME" || { say "== Cloudflare login will open a URL. Complete it, then return =="; cloudflared tunnel login; cloudflared tunnel create "$TUNNEL_NAME"; }
  TUNNEL_ID=$(cloudflared tunnel list | awk -v n="$TUNNEL_NAME" '$2==n{print $1}')
  cloudflared tunnel route dns "$TUNNEL_NAME" "$FQDN" || warn "(DNS) Record for ${FQDN} already exists — continuing"
  mkdir -p /etc/cloudflared
  cat > /etc/cloudflared/config.yml <<YAML
tunnel: ${TUNNEL_ID}
credentials-file: /root/.cloudflared/${TUNNEL_ID}.json
ingress:
  - hostname: ${FQDN}
    service: http://127.0.0.1:80
  - service: http_status:404
YAML
  cat > /etc/systemd/system/cloudflared.service <<SYS
[Unit]
Description=Cloudflare Tunnel for ${FQDN}
After=network.target
[Service]
ExecStart=$(command -v cloudflared) --no-autoupdate tunnel --config /etc/cloudflared/config.yml run
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
SYS
  systemctl daemon-reload; systemctl enable --now cloudflared || true
fi

# ---------------- DEV: code-server + editable worktree ----------------
if [[ "$MODE" == "dev" ]]; then
  id -u coder >/dev/null 2>&1 || useradd -m -s /bin/bash coder
  curl -fsSL https://code-server.dev/install.sh | bash
  install -d -o coder -g coder /home/coder/.config/code-server
  cat > /home/coder/.config/code-server/config.yaml <<YML
bind-addr: 127.0.0.1:8080
auth: none
cert: false
YML
  chown -R coder:coder /home/coder/.config
  mkdir -p /etc/systemd/system/code-server@coder.service.d
  cat > /etc/systemd/system/code-server@coder.service.d/override.conf <<OVR
[Service]
UMask=0002
OVR
  systemctl daemon-reload
  systemctl enable --now code-server@coder

  # coder git identity
  as_user coder "git config --global user.name '${GIT_NAME}'"
  as_user coder "git config --global user.email '${GIT_EMAIL}'"
  as_user coder "git config --global init.defaultBranch '${DEFAULT_BRANCH}'"

  # Deploy key for dev
  install -d -m 700 -o coder -g coder /home/coder/.ssh
  DEV_KEY="/home/coder/.ssh/${FQDN}_dev_ed25519"
  if [[ ! -f "$DEV_KEY" ]]; then as_user coder "ssh-keygen -t ed25519 -N '' -f '$DEV_KEY' -C 'dev-${FQDN}'"; fi
  touch /home/coder/.ssh/known_hosts; chown coder:coder /home/coder/.ssh/known_hosts; chmod 600 /home/coder/.ssh/known_hosts
  ssh-keyscan -H github.com >> /home/coder/.ssh/known_hosts 2>/dev/null || true
  cat > /home/coder/.ssh/config <<CFG
Host github.com
  HostName github.com
  User git
  IdentityFile ${DEV_KEY}
  IdentitiesOnly yes
CFG
  chown coder:coder /home/coder/.ssh/config; chmod 600 /home/coder/.ssh/config

  say "\n==== Add this DEPLOY KEY to ${GH_USER}/${GH_REPO} (Allow write access)"
  echo "-----8<----- DEV DEPLOY PUBLIC KEY -----8<-----"; cat "${DEV_KEY}.pub"; echo "-----8<----- END -----8<-----"

  REPO_SSH="git@github.com:${GH_USER}/${GH_REPO}.git"
  while ! as_user coder "git ls-remote '${REPO_SSH}' HEAD >/dev/null 2>&1"; do err "Deploy key not yet permitted for ${GH_USER}/${GH_REPO}. Add it and press Enter."; read -r _ || true; done

  install -d -m 2775 -o coder -g www-data "$WORKTREE"
  setfacl -R -m u:coder:rwX,g:www-data:rwX "$WORKTREE" || true
  setfacl -dR -m u:coder:rwX,g:www-data:rwX "$WORKTREE" || true

  if [[ ! -d "$WORKTREE/.git" || -z $(ls -A "$WORKTREE" 2>/dev/null) ]]; then
    as_user coder "git clone --branch '${DEFAULT_BRANCH}' '${REPO_SSH}' '${WORKTREE}'"
  else
    as_user coder "cd '${WORKTREE}' && git remote set-url origin '${REPO_SSH}' && git fetch --all --prune && git checkout '${DEFAULT_BRANCH}' && git pull --ff-only || true"
  fi
  as_user coder "cd '${WORKTREE}' && git config user.name '${GIT_NAME}' && git config user.email '${GIT_EMAIL}'" || true

  # Apache needs to read the codebase
  id -nG coder | grep -qw www-data || usermod -aG www-data coder || true
  setfacl -R  -m g:www-data:rX "$WORKTREE" || true
  setfacl -dR -m g:www-data:rX "$WORKTREE" || true

  # --- NEW: rewrite vhost with the real docroot ---
  DOCROOT="$WORKTREE"; [[ -d "${WORKTREE}/public" ]] && DOCROOT="${WORKTREE}/public"
  cat > "$VHOST_CONF" <<'APACHE'
<VirtualHost *:80>
  ServerName __SITE__
  ServerAdmin webmaster@localhost
  DocumentRoot __DOCROOT__

  <Directory __DOCROOT__>
    AllowOverride All
    Require all granted
    Options FollowSymLinks
    DirectoryIndex index.php index.html index.xhtml index.htm
  </Directory>

  ProxyPreserveHost On
  RewriteEngine On
  RewriteCond %{HTTP:Upgrade} =websocket [NC]
  RewriteRule ^__CODE_PATH__/(.*)$ ws://127.0.0.1:8080/$1 [P,L]
  RewriteCond %{HTTP:Upgrade} !=websocket [NC]
  RewriteRule ^__CODE_PATH__/(.*)$ http://127.0.0.1:8080/$1 [P,L]
  ProxyPassReverse __CODE_PATH__/ http://127.0.0.1:8080/

  Alias /hooks/github /opt/__SITE__/hooks/github-webhook.php
  <Directory /opt/__SITE__/hooks>
    Require all granted
    Options FollowSymLinks
  </Directory>

  RemoteIPHeader CF-Connecting-IP
  RemoteIPTrustedProxy 127.0.0.1
  ErrorLog /var/log/apache2/__SITE__-error.log
  CustomLog /var/log/apache2/__SITE__-access.log combined
</VirtualHost>
APACHE
  sed -i -e "s#__SITE__#${FQDN}#g" -e "s#__DOCROOT__#${DOCROOT}#g" -e "s@__CODE_PATH__@${CODE_PATH}@g" "$VHOST_CONF"
  a2enmod dir >/dev/null || true
  apachectl configtest && systemctl reload apache2 || true

  say "Dev workspace ready: ${WORKTREE}. Runtime dirs bind‑mounted from ${SHARED_DIR}."
  say "Edit at https://${FQDN}${CODE_PATH}/ and push from the editor."
fi

# ---------------- PRODUCTION: releases + deploy service + webhook (unchanged) ----------------
if [[ "$MODE" == "production" ]]; then
  SSH_DIR="/root/.ssh"; mkdir -p "$SSH_DIR"; chmod 700 "$SSH_DIR"
  KEY_PREFIX="${SSH_DIR}/${FQDN}_deploy_ed25519"
  if [[ ! -f "${KEY_PREFIX}" ]]; then ssh-keygen -t ed25519 -N "" -f "${KEY_PREFIX}" -C "deploy-${FQDN}"; say "\n==== Add this DEPLOY KEY (read‑only) to GitHub: ${GH_USER}/${GH_REPO}"; echo "-----8<----- PUBLIC KEY -----8<-----"; cat "${KEY_PREFIX}.pub"; echo "-----8<----- END -----8<-----"; fi
  ssh-keyscan -H github.com >> "${SSH_DIR}/known_hosts" 2>/dev/null || true
  REPO_SSH="git@github.com:${GH_USER}/${GH_REPO}.git"
  while ! GIT_SSH_COMMAND="ssh -i ${KEY_PREFIX} -o StrictHostKeyChecking=yes" git ls-remote "$REPO_SSH" HEAD >/dev/null 2>&1; do err "Deploy key not yet permitted. Add the key above to the repo and press Enter to retry."; read -r _ || true; done

  printf '%s\n' production > "${ETC_SITE}/mode"; printf '%s\n' "$DEFAULT_BRANCH" > "${ETC_SITE}/branch"; printf '%s\n' "$TAG_PATTERN" > "${ETC_SITE}/tag_pattern"; printf '%s\n' "$DATA_ROOT" > "${ETC_SITE}/data_root"; printf '%s\n' "$WRITABLE_DIRS" > "${ETC_SITE}/writable"; printf '%s\n' "$REPO_SSH" > "${ETC_SITE}/repo_ssh"; printf '%s\n' "$KEY_PREFIX" > "${ETC_SITE}/ssh_key"

  DEPLOY_SCRIPT="/usr/local/bin/deploy-site.sh"
  cat > "$DEPLOY_SCRIPT" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
SITE="$1"; SITE_ROOT="/var/www/${SITE}"; RELEASES_DIR="${SITE_ROOT}/releases"; CURRENT_LINK="${SITE_ROOT}/current"; ETC_SITE="/etc/${SITE}"
DATA_ROOT=$(cat "${ETC_SITE}/data_root"); SHARED_DIR="${DATA_ROOT}/shared"; SQLITE_DIR="${DATA_ROOT}/sqlite"; WRITABLE_DIRS=$(cat "${ETC_SITE}/writable"); MODE=$(cat "${ETC_SITE}/mode"); BRANCH=$(cat "${ETC_SITE}/branch"); TAG_PATTERN=$(cat "${ETC_SITE}/tag_pattern"); REPO_SSH=$(cat "${ETC_SITE}/repo_ssh"); KEY_PATH=$(cat "${ETC_SITE}/ssh_key")
LOGFILE="/var/log/deploy-${SITE}.log"; ENV_FILE="/etc/${SITE}/.env"; VHOST_CONF="/etc/apache2/sites-available/${SITE}.conf"
log(){ echo "[$(date +'%F %T')] $*" | tee -a "$LOGFILE"; }; fail(){ log "ERROR: $*"; exit 1; }
mkdir -p "$RELEASES_DIR" "$SHARED_DIR" "$SQLITE_DIR"; chown -R www-data:www-data "$SHARED_DIR" "$SQLITE_DIR"; chmod -R 750 "$SHARED_DIR" "$SQLITE_DIR"
latest_tag(){ GIT_SSH_COMMAND="ssh -i ${KEY_PATH} -o StrictHostKeyChecking=yes" git ls-remote --tags --refs "$REPO_SSH" | awk '{print $2}' | sed -e 's#refs/tags/##' | grep -E "^${TAG_PATTERN//\*/.*}$" | sort -V | tail -n1; }
clone_ref(){ local ref="$1" dest="$2"; GIT_SSH_COMMAND="ssh -i ${KEY_PATH} -o StrictHostKeyChecking=yes" git clone --depth 1 --branch "$ref" "$REPO_SSH" "$dest" 2>>"$LOGFILE" || fail "git clone failed (ref=$ref)."; }
link_shared(){ local dest="$1"; for d in $WRITABLE_DIRS; do mkdir -p "${SHARED_DIR}/${d}"; rm -rf "${dest}/${d}" 2>/dev/null || true; ln -s "${SHARED_DIR}/${d}" "${dest}/${d}"; done; if [[ ! -f "$ENV_FILE" ]]; then mkdir -p "/etc/${SITE}"; cat > "$ENV_FILE" <<ENV
APP_ENV=production
APP_DEBUG=false
SQLITE_DIR=${SQLITE_DIR}
ENV
chmod 640 "$ENV_FILE"; chown root:www-data "$ENV_FILE"; fi; ln -sfn "$ENV_FILE" "${dest}/.env" 2>/dev/null || true; }
run_composer(){ local dest="$1"; if command -v composer >/dev/null 2>&1; then [[ -f "${dest}/composer.json" ]] && (cd "$dest" && COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader 2>>"$LOGFILE") || true; find "$dest" -type f -name composer.json -not -path "*/vendor/*" -not -path "${dest}/composer.json" -printf '%h\n' | sort -u | while read -r sub; do (cd "$sub" && COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader 2>>"$LOGFILE") || true; done; fi; }
switch_current(){ local new="$1"; [[ -L "$CURRENT_LINK" ]] && ln -sfn "$(readlink -f "$CURRENT_LINK")" "${SITE_ROOT}/previous" || true; ln -sfn "$new" "$CURRENT_LINK"; }
prune_releases(){ ls -1dt ${RELEASES_DIR}/* 2>/dev/null | tail -n +6 | xargs -r rm -rf; }
write_vhost(){ local docroot="$1"; cat > "$VHOST_CONF" <<'APACHE'
<VirtualHost *:80>
  ServerName __SITE__
  ServerAdmin webmaster@localhost
  DocumentRoot __DOCROOT__

  <Directory __DOCROOT__>
    AllowOverride All
    Require all granted
    Options FollowSymLinks
    DirectoryIndex index.php index.html index.xhtml index.htm
  </Directory>

  ProxyPreserveHost On
  RewriteEngine On
  RewriteCond %{HTTP:Upgrade} =websocket [NC]
  RewriteRule ^/code/(.*)$ ws://127.0.0.1:8080/$1 [P,L]
  RewriteCond %{HTTP:Upgrade} !=websocket [NC]
  RewriteRule ^/code/(.*)$ http://127.0.0.1:8080/$1 [P,L]
  ProxyPassReverse /code/ http://127.0.0.1:8080/

  Alias /hooks/github /opt/__SITE__/hooks/github-webhook.php
  <Directory /opt/__SITE__/hooks>
    Require all granted
    Options FollowSymLinks
  </Directory>

  RemoteIPHeader CF-Connecting-IP
  RemoteIPTrustedProxy 127.0.0.1
  ErrorLog /var/log/apache2/__SITE__-error.log
  CustomLog /var/log/apache2/__SITE__-access.log combined
</VirtualHost>
APACHE
  sed -i -e "s#__SITE__#${SITE}#g" -e "s#__DOCROOT__#${docroot}#g" "$VHOST_CONF"
}
reload_apache(){ apachectl configtest || fail "apache2 configtest failed"; systemctl reload apache2 || true; }
main(){ local ref=""; ref=$(latest_tag); if [[ -z "$ref" ]]; then log "No tag matches pattern '${TAG_PATTERN}'. Nothing to deploy."; exit 0; fi; local already=""; [[ -L "$CURRENT_LINK" && -f "${CURRENT_LINK}/.deploy_ref" ]] && already=$(cat "${CURRENT_LINK}/.deploy_ref") || true; if [[ "$already" == "$ref" ]] ; then log "Already on $ref"; exit 0; fi; local ts tgt; ts=$(date +%Y%m%d%H%M%S); tgt="${RELEASES_DIR}/${ts}-${ref}"; log "Deploying $ref -> $tgt"; clone_ref "$ref" "$tgt"; link_shared "$tgt"; run_composer "$tgt"; echo "$ref" > "${tgt}/.deploy_ref"; chown -R www-data:www-data "$tgt"; switch_current "$tgt"; prune_releases; local docroot="$CURRENT_LINK"; [[ -d "${CURRENT_LINK}/public" ]] && docroot="${CURRENT_LINK}/public"; write_vhost "$docroot"; reload_apache; log "Deploy complete: $ref"; }
main "$@"
BASH
  chmod +x "$DEPLOY_SCRIPT"

  # systemd service
  cat > /etc/systemd/system/deploy@.service <<SERVICE
[Unit]
Description=Deploy site %i
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=${DEPLOY_SCRIPT} %i
User=root
Group=root
[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload

  # Webhook (prod only)
  WEBHOOK_SECRET_FILE="${ETC_SITE}/webhook.secret"; [[ -f "$WEBHOOK_SECRET_FILE" ]] || head -c 32 /dev/urandom | base64 > "$WEBHOOK_SECRET_FILE"
  WEBHOOK_SECRET=$(cat "$WEBHOOK_SECRET_FILE")
  mkdir -p "$HOOKS_DIR"
  cat > "${HOOKS_DIR}/github-webhook.php" <<'PHP'
<?php
$secret = trim(file_get_contents('__SECRET_FILE__'));
$sig = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
$event = $_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';
$payload = file_get_contents('php://input');
function bad($c){ http_response_code($c); exit; }
if (empty($sig) || empty($event)) bad(400);
$calc = 'sha256=' . hash_hmac('sha256', $payload, $secret);
if (!hash_equals($calc, $sig)) bad(403);
$data = json_decode($payload, true);
if ($event === 'release' && ($data['action'] ?? '') === 'published') { @exec('systemctl start deploy@__FQDN__.service > /dev/null 2>&1 &'); http_response_code(202); echo 'deploy queued'; exit; }
http_response_code(204);
PHP
  sed -i -e "s@__SECRET_FILE__@${WEBHOOK_SECRET_FILE}@g" -e "s@__FQDN__@${FQDN}@g" "${HOOKS_DIR}/github-webhook.php"
  chown -R www-data:www-data "$HOOKS_DIR"; chmod 640 "$HOOKS_DIR/github-webhook.php"

  systemctl start "deploy@${FQDN}.service" || true
  say "Saved selections to: $CONFIG_FILE"
  say "Webhook URL: https://${FQDN}/hooks/github"; echo "Webhook secret: ${WEBHOOK_SECRET}"
fi

# ---------------- Final summary ----------------
DOC_NOW="/var/www/html"; if [[ "$MODE" == "dev" ]]; then DOC_NOW="$WORKTREE"; [[ -d "$WORKTREE/public" ]] && DOCROOT="${WORKTREE}/public" && DOC_NOW="$DOCROOT"; fi
say "============================================================"; say "SETUP COMPLETE for ${FQDN} (${MODE})."; echo "Data root: ${DATA_ROOT}  |  SQLite: ${SQLITE_DIR}"; if [[ "$MODE" == "dev" ]]; then echo "Dev worktree: ${WORKTREE}"; echo "Edit at: https://${FQDN}${CODE_PATH}/  (lock it with Cloudflare Access)"; else echo "Deploy script: /usr/local/bin/deploy-site.sh  |  systemd unit: deploy@${FQDN}.service"; echo "Log: /var/log/deploy-${FQDN}.log"; fi; echo "Apache docroot now: ${DOC_NOW}"; say "Selections saved to $CONFIG_FILE  (copy this file with setup.sh to reuse)"; say "============================================================"

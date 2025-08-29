#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# TurnKey LAMP one‑shot setup — v2.4
# Changes from v2.3:
#   • DEV now prompts for Git author.name and author.email and configures them
#     for user 'coder' (global + repo-local). Defaults: name=$GH_USER, email=dev@$FQDN
#   • Rest unchanged: DEV uses bind mounts for runtime dirs; no sudo used.
# =============================================================

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
say(){ echo -e "\e[1;32m$*\e[0m"; }
warn(){ echo -e "\e[33m$*\e[0m"; }
err(){ echo -e "\e[31m$*\e[0m"; }
prompt(){ local q="$1" d="${2-}" a; if [[ -n "$d" ]]; then read -rp "$q [$d]: " a || true; echo "${a:-$d}"; else read -rp "$q: " a || true; echo "$a"; fi; }

have_pkg(){ local p="$1"; local c; c=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/{print $2}'); [[ -n "$c" && "$c" != "(none)" ]]; }
apt_install(){ local to=() sk=(); for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 && continue; have_pkg "$p" && to+=("$p") || sk+=("$p"); done; if ((${#to[@]})); then apt-get update -yq; apt-get install -yq --no-install-recommends "${to[@]}"; fi; ((${#sk[@]})) && warn "[info] Skipping unavailable: ${sk[*]}" || true; }

as_user(){ local u="$1"; shift; runuser -u "$u" -- bash -lc "$*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

# ---- Load previous answers if available ----
DEFAULTS_DIR="/etc/tkl-setup"; DEFAULTS_FILE="${DEFAULTS_DIR}/defaults.env"
set +u; [[ -f "$DEFAULTS_FILE" ]] && . "$DEFAULTS_FILE"; set -u

# ---- Base packages ----
apt_install ca-certificates curl git unzip jq acl apache2 php php-cli php-curl php-sqlite3 php-mbstring php-gd libapache2-mod-php php-zip php-xml php-intl

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
# NEW in v2.4
GIT_NAME=$(prompt "[dev] Git author.name" "${GIT_NAME:-$GH_USER}")
GIT_EMAIL=$(prompt "[dev] Git author.email" "${GIT_EMAIL:-dev@${FQDN}}")

DATA_ROOT_DEFAULT="${DATA_ROOT:-/srv/${FQDN}}"
DATA_ROOT=$(prompt "Data root (shared runtime data & SQLite)" "$DATA_ROOT_DEFAULT")
DATA_DEV=$(prompt "(Optional) Device path for dedicated data disk (WILL FORMAT if provided, e.g. /dev/sdb)" "")

CODE_PATH="${CODE_PATH:-/code}"            # where code-server is exposed
SITE_ROOT="/var/www/${FQDN}"
RELEASES_DIR="${SITE_ROOT}/releases"
CURRENT_LINK="${SITE_ROOT}/current"
WORKTREE="${SITE_ROOT}/app"                 # dev-only working copy
SHARED_DIR="${DATA_ROOT}/shared"
SQLITE_DIR="${DATA_ROOT}/sqlite"
HOOKS_DIR="/opt/${FQDN}/hooks"
ETC_SITE="/etc/${FQDN}"

mkdir -p "$RELEASES_DIR" "$SHARED_DIR" "$SQLITE_DIR" "$HOOKS_DIR" "$ETC_SITE" "$DEFAULTS_DIR" "$SITE_ROOT"

# Persist answers for next run
cat > "$DEFAULTS_FILE" <<EOF
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
EOF

# ---------------- Optional data disk ----------------
if [[ -n "$DATA_DEV" ]]; then
  echo; err "*** WARNING: Will format ${DATA_DEV} as ext4 and mount at ${DATA_ROOT} ***"; read -rp "Type 'FORMAT' to proceed, or press Enter to skip: " C || true
  if [[ "$C" == "FORMAT" ]]; then
    umount "$DATA_DEV" 2>/dev/null || true
    mkfs.ext4 -F "$DATA_DEV"
    mkdir -p "$DATA_ROOT"
    UUID=$(blkid -s UUID -o value "$DATA_DEV"); grep -q "$UUID" /etc/fstab || echo "UUID=$UUID  $DATA_ROOT  ext4  noatime,nodiratime  0  2" >> /etc/fstab
    mount -a
  else say "Skipped disk format. Using existing FS at $DATA_ROOT"; fi
fi
chown -R www-data:www-data "$DATA_ROOT"; chmod -R 750 "$DATA_ROOT"

# ---------------- Move any *.db to SQLITE_DIR ----------------
shopt -s nullglob; for db in *.db; do say "+ Moving $db -> $SQLITE_DIR/"; mv -f "$db" "$SQLITE_DIR/"; done; shopt -u nullglob
chown -R www-data:www-data "$SQLITE_DIR"; chmod -R 750 "$SQLITE_DIR"
# Pre-create ACLs for shared areas
setfacl -R -m g:www-data:rwX "$SQLITE_DIR" "$SHARED_DIR" || true
setfacl -dR -m g:www-data:rwX "$SQLITE_DIR" "$SHARED_DIR" || true

# ---------------- Apache global ServerName & vhost ----------------
mkdir -p /etc/apache2/conf-available
cat > "/etc/apache2/conf-available/servername-${FQDN}.conf" <<CONF
ServerName ${FQDN}
CONF
a2enconf "servername-${FQDN}" >/dev/null || true

# need wstunnel for code-server
a2enmod proxy proxy_http proxy_wstunnel headers rewrite alias remoteip >/dev/null || true

VHOST_CONF="/etc/apache2/sites-available/${FQDN}.conf"
cat > "$VHOST_CONF" <<APACHE
<VirtualHost *:80>
  ServerName ${FQDN}
  ServerAdmin webmaster@localhost

  DocumentRoot /var/www/html
  <Directory /var/www/>
    AllowOverride All
    Require all granted
    Options FollowSymLinks
  </Directory>

  # /code -> code-server
  ProxyPreserveHost On
  RewriteEngine On
  # WebSocket upgrade
  RewriteCond %{HTTP:Upgrade} =websocket [NC]
  RewriteRule ^${CODE_PATH}/(.*)$ ws://127.0.0.1:8080/\$1 [P,L]
  # Plain HTTP
  RewriteCond %{HTTP:Upgrade} !=websocket [NC]
  RewriteRule ^${CODE_PATH}/(.*)$ http://127.0.0.1:8080/\$1 [P,L]
  ProxyPassReverse ${CODE_PATH}/ http://127.0.0.1:8080/

  # GitHub webhook endpoint (prod only behavior; dev returns 204)
  Alias /hooks/github ${HOOKS_DIR}/github-webhook.php
  <Directory ${HOOKS_DIR}>
    Require all granted
    Options FollowSymLinks
  </Directory>

  RemoteIPHeader CF-Connecting-IP
  RemoteIPTrustedProxy 127.0.0.1

  ErrorLog \${APACHE_LOG_DIR}/${FQDN}-error.log
  CustomLog \${APACHE_LOG_DIR}/${FQDN}-access.log combined
</VirtualHost>
APACHE

a2dissite 000-default >/dev/null 2>&1 || true
a2ensite "$FQDN" >/dev/null
apachectl configtest && systemctl reload apache2 || true

# ---------------- Cloudflared (Tunnel) ----------------
if ! command -v cloudflared >/dev/null 2>&1; then
  say "+ Installing cloudflared"
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
  . /etc/os-release; CODENAME="${VERSION_CODENAME:-bookworm}"
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared ${CODENAME} main" > /etc/apt/sources.list.d/cloudflared.list
  apt-get update -yq; apt-get install -yq cloudflared
fi
TUNNEL_NAME="tkl-${FQDN}"
cloudflared tunnel list 2>/dev/null | awk '{print $2}' | grep -qx "$TUNNEL_NAME" || { say "== Cloudflare login will open a URL. Complete it, then return =="; cloudflared tunnel login; cloudflared tunnel create "$TUNNEL_NAME"; }
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
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel --config /etc/cloudflared/config.yml run
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
SYS
systemctl daemon-reload; systemctl enable --now cloudflared

# ---------------- DEV: code-server + editable worktree (with repo Deploy Key) ----------------
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
  # Ensure group-friendly umask for new files from code-server
  mkdir -p /etc/systemd/system/code-server@coder.service.d
  cat > /etc/systemd/system/code-server@coder.service.d/override.conf <<OVR
[Service]
UMask=0002
OVR
  systemctl daemon-reload
  systemctl enable --now code-server@coder

  # Configure coder's Git identity (global)
  as_user coder "git config --global user.name '${GIT_NAME}'"
  as_user coder "git config --global user.email '${GIT_EMAIL}'"
  as_user coder "git config --global init.defaultBranch '${DEFAULT_BRANCH}'"

  # Deploy Key for dev (attach to repo with **Allow write access**)
  install -d -m 700 -o coder -g coder /home/coder/.ssh
  DEV_KEY="/home/coder/.ssh/${FQDN}_dev_ed25519"
  if [[ ! -f "$DEV_KEY" ]]; then
    as_user coder "ssh-keygen -t ed25519 -N '' -f '$DEV_KEY' -C 'dev-${FQDN}'"
  fi
  touch /home/coder/.ssh/known_hosts; chown coder:coder /home/coder/.ssh/known_hosts; chmod 600 /home/coder/.ssh/known_hosts
  ssh-keyscan -H github.com >> /home/coder/.ssh/known_hosts 2>/dev/null || true
  # SSH config so git from the editor uses this key automatically
  cat > /home/coder/.ssh/config <<CFG
Host github.com
  HostName github.com
  User git
  IdentityFile ${DEV_KEY}
  IdentitiesOnly yes
CFG
  chown coder:coder /home/coder/.ssh/config; chmod 600 /home/coder/.ssh/config

  say "\n==== Add this DEPLOY KEY to ${GH_USER}/${GH_REPO} (check: Allow write access)"
  echo "-----8<----- DEV DEPLOY PUBLIC KEY -----8<-----"; cat "${DEV_KEY}.pub"; echo "-----8<----- END -----8<-----"

  REPO_SSH="git@github.com:${GH_USER}/${GH_REPO}.git"
  # Wait until the key works (no HTTPS fallback)
  while ! as_user coder "git ls-remote '${REPO_SSH}' HEAD >/dev/null 2>&1"; do
    err "Deploy key not yet permitted for ${GH_USER}/${GH_REPO}. Add it with WRITE access and press Enter to retry."; read -r _ || true
  done

  # Prepare worktree directory OWNED by coder before cloning
  install -d -m 2775 -o coder -g www-data "$WORKTREE"
  setfacl -R -m u:coder:rwX,g:www-data:rwX "$WORKTREE" || true
  setfacl -dR -m u:coder:rwX,g:www-data:rwX "$WORKTREE" || true

  if [[ ! -d "$WORKTREE/.git" || -z $(ls -A "$WORKTREE" 2>/dev/null) ]]; then
    as_user coder "git clone --branch '${DEFAULT_BRANCH}' '${REPO_SSH}' '${WORKTREE}'"
  else
    as_user coder "cd '${WORKTREE}' && git remote set-url origin '${REPO_SSH}' && git fetch --all --prune && git checkout '${DEFAULT_BRANCH}' && git pull --ff-only || true"
  fi
  # Ensure repo-local identity as well (overrides global if needed)
  as_user coder "cd '${WORKTREE}' && git config user.name '${GIT_NAME}' && git config user.email '${GIT_EMAIL}'"

  ensure_bind(){
    local rel="$1"; local mp="$WORKTREE/$rel"; local tgt="$SHARED_DIR/$rel"
    if [[ -L "$mp" ]]; then rm -f "$mp"; fi
    mkdir -p "$tgt" "$mp"
    chown -R www-data:www-data "$tgt"; chmod -R 770 "$tgt"
    setfacl -R -m u:coder:rwX,g:www-data:rwX "$tgt" || true
    setfacl -dR -m u:coder:rwX,g:www-data:rwX "$tgt" || true
    chown coder:www-data "$mp"; chmod 2775 "$mp"
    setfacl -R -m u:coder:rwX,g:www-data:rwX "$mp" || true
    setfacl -dR -m u:coder:rwX,g:www-data:rwX "$mp" || true
    if ! mountpoint -q "$mp"; then
      if [[ -n $(ls -A "$mp" 2>/dev/null) ]]; then rsync -a "$mp"/ "$tgt"/; fi
    fi
    if ! mountpoint -q "$mp"; then mount --bind "$tgt" "$mp"; fi
    local fstab_line="$tgt $mp none bind 0 0"; grep -qsF "$fstab_line" /etc/fstab || echo "$fstab_line" >> /etc/fstab
  }
  for d in $WRITABLE_DIRS; do ensure_bind "$d"; done

  # Composer as coder (root + subfolders)
  if [[ -f "${WORKTREE}/composer.json" ]]; then as_user coder "cd '${WORKTREE}' && composer install --prefer-dist --no-interaction"; fi
  find "${WORKTREE}" -type f -name composer.json -not -path "*/vendor/*" -not -path "${WORKTREE}/composer.json" -printf '%h\n' | sort -u | while read -r sub; do as_user coder "cd '${sub}' && composer install --prefer-dist --no-interaction" || true; done

  # Vhost docroot to worktree(/public)
  DOCROOT="$WORKTREE"; [[ -d "${WORKTREE}/public" ]] && DOCROOT="${WORKTREE}/public"
  sed -i \
    -e "s#^\s*DocumentRoot\s\+.*#  DocumentRoot ${DOCROOT}#" \
    -e "/<Directory \/var\/www\/>/,/<\/Directory>/c\  <Directory ${DOCROOT}>\n    AllowOverride All\n    Require all granted\n    Options FollowSymLinks\n  </Directory>" \
    "$VHOST_CONF"
  apachectl configtest && systemctl reload apache2 || true

  say "Dev workspace ready: ${WORKTREE}. Runtime dirs are bind-mounted from ${SHARED_DIR}."
  say "Edit at https://${FQDN}${CODE_PATH}/ and push from the editor."
fi

# ---------------- PRODUCTION: releases + deploy service + webhook ----------------
Options FollowSymLinks
</Directory>
ProxyPreserveHost On
RewriteEngine On
RewriteCond %{HTTP:Upgrade} =websocket [NC]
RewriteRule ^/code/(.*)$ ws://127.0.0.1:8080/\$1 [P,L]
RewriteCond %{HTTP:Upgrade} !=websocket [NC]
RewriteRule ^/code/(.*)$ http://127.0.0.1:8080/\$1 [P,L]
ProxyPassReverse /code/ http://127.0.0.1:8080/
Alias /hooks/github /opt/${SITE}/hooks/github-webhook.php
<Directory /opt/${SITE}/hooks>
Require all granted
Options FollowSymLinks
</Directory>
RemoteIPHeader CF-Connecting-IP
RemoteIPTrustedProxy 127.0.0.1
ErrorLog \${APACHE_LOG_DIR}/${SITE}-error.log
CustomLog \${APACHE_LOG_DIR}/${SITE}-access.log combined
</VirtualHost>
APACHE
}
reload_apache(){ apachectl configtest || fail "apache2 configtest failed"; systemctl reload apache2 || true; }
main(){ local ref=""; ref=$(latest_tag); [[ -z "$ref" ]] && { log "No tag matches $TAG_PATTERN"; exit 0; }; local already=""; [[ -L "$CURRENT_LINK" && -f "${CURRENT_LINK}/.deploy_ref" ]] && already=$(cat "${CURRENT_LINK}/.deploy_ref") || true; if [[ "$already" == "$ref" ]]; then log "Already on $ref"; exit 0; fi; local ts tgt; ts=$(date +%Y%m%d%H%M%S); tgt="${RELEASES_DIR}/${ts}-${ref}"; log "Deploying $ref -> $tgt"; clone_ref "$ref" "$tgt"; link_shared "$tgt"; run_composer "$tgt"; echo "$ref" > "${tgt}/.deploy_ref"; chown -R www-data:www-data "$tgt"; switch_current "$tgt"; prune_releases; local docroot="$CURRENT_LINK"; [[ -d "${CURRENT_LINK}/public" ]] && docroot="${CURRENT_LINK}/public"; write_vhost "$docroot"; reload_apache; log "Deploy complete: $ref"; }
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
cat > "${HOOKS_DIR}/github-webhook.php" <<PHP
<?php
\$secret = trim(file_get_contents('${WEBHOOK_SECRET_FILE}'));
\$sig = \$_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
\$event = \$_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';
\$payload = file_get_contents('php://input');
function bad(\$c){ http_response_code(\$c); exit; }
if (empty(\$sig) || empty(\$event)) bad(400);
\$calc = 'sha256=' . hash_hmac('sha256', \$payload, \$secret);
if (!hash_equals(\$calc, \$sig)) bad(403);
\$data = json_decode(\$payload, true);
if (\$event === 'release' && (\$data['action'] ?? '') === 'published') { @exec('systemctl start deploy@${FQDN}.service > /dev/null 2>&1 &'); http_response_code(202); echo 'deploy queued'; exit; }
http_response_code(204);
PHP
chown -R www-data:www-data "$HOOKS_DIR"; chmod 640 "$HOOKS_DIR/github-webhook.php"


# Initial deploy and webhook summary
systemctl start "deploy@${FQDN}.service" || true
say "Webhook URL: https://${FQDN}/hooks/github"; echo "Webhook secret: ${WEBHOOK_SECRET}"
fi

# ---------------- Final summary ----------------
DOC_NOW="/var/www/html"
if [[ "$MODE" == "dev" ]]; then DOC_NOW="$WORKTREE"; [[ -d "$WORKTREE/public" ]] && DOC_NOW="$WORKTREE/public"; fi
say "============================================================"
say "SETUP COMPLETE for ${FQDN} (${MODE})."
echo "Data root: ${DATA_ROOT}  |  SQLite: ${SQLITE_DIR}"
if [[ "$MODE" == "dev" ]]; then
  echo "Dev worktree: ${WORKTREE}"
  echo "Edit at: https://${FQDN}${CODE_PATH}/  (lock it with Cloudflare Access)"
else
  echo "Deploy script: /usr/local/bin/deploy-site.sh  |  systemd unit: deploy@${FQDN}.service"
  echo "Log: /var/log/deploy-${FQDN}.log"
fi
echo "Apache docroot now: ${DOC_NOW}"
say "============================================================"

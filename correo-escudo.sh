#!/usr/bin/env bash
# =============================================================================
#  correo-escudo — Protección del correo para pymes (Blue Team)
#
#  Dos herramientas en una:
#    dominio   Revisa si tu dominio de correo se puede SUPLANTAR: SPF, DKIM,
#              DMARC, MTA-STS, TLS-RPT y DNSSEC, con una nota de la A a la F y
#              los registros exactos que hay que publicar para arreglarlo.
#    analizar  Revisa un correo sospechoso (.eml) y busca señales de phishing:
#              remitente falso, fraude "del jefe", cambio de cuenta bancaria,
#              enlaces engañosos y adjuntos peligrosos.
#
#  GARANTÍA DE DISEÑO: solo lee. "dominio" hace consultas DNS públicas (lo
#  mismo que hace cualquier servidor de correo del mundo). "analizar" NO usa
#  la red: nunca abre los enlaces ni los adjuntos del correo.
#
#  Normas: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 9989 (DMARC, 2026),
#  RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 7505 (MX nulo),
#  requisitos de Google, Yahoo y Microsoft para remitentes, CIS Controls 9.
#
#  Licencia: MIT
# =============================================================================

set -uo pipefail

# --- Endurecimiento del propio script -------------------------------------------
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C
unset POSIXLY_CORRECT        # en modo POSIX, sed no acepta los rangos de bytes que limpian la salida
umask 077
shopt -u patsub_replacement 2>/dev/null || true

readonly VERSION="1.1.0"

# --- Opciones -------------------------------------------------------------------
COMMAND=""
TARGET=""
FORMAT="text"
OUTPUT_FILE=""
USE_COLOR=1
RESOLVER=""
SELECTORS=()
FAIL_ON="high"
MY_DOMAINS=""
MARCAS_FILE=""
NO_HTTPS=0
ANON=0
DETAIL=0
TARGETS=()

# Respuestas DNS simuladas: SOLO para las pruebas automáticas (sin red)
DNS_FILE=${CORREO_ESCUDO_DNS_FILE:-}

C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_GRY=""; C_BLD=""; C_RST=""

usage() {
    cat <<EOF
correo-escudo v${VERSION} — Protección del correo para pymes

Uso:
  $0 dominio DOMINIO [opciones]     ¿Se puede suplantar el correo de este dominio?
  $0 lista ARCHIVO [opciones]       Revisa muchos dominios (uno por línea)
  $0 analizar CORREO.eml [opciones] ¿Este correo es phishing?

Opciones de "dominio" y "lista":
      --selector NOMBRE  Selector DKIM a comprobar (se puede repetir). Si no se
                         indica, se prueban los más comunes (Google, Microsoft...)
      --resolver IP      Servidor DNS a usar (def: el del sistema)
      --no-https         No descarga la política MTA-STS (solo DNS)

Opciones de "analizar":
      --mi-dominio LISTA Tus dominios, separados por comas: detecta imitaciones
                         como "ernpresa.com" o "empresa-pa.com"
      --marcas ARCHIVO   Marcas extra a vigilar (formato en el README)

Comunes:
      --format FORMATO   text (def) o json
  -o, --output ARCHIVO   Guarda el informe en ARCHIVO (permisos 600)
      --fail-on SEV      Código de salida 1 desde esta severidad (def: high)
      --no-color         Sin colores
  -h, --help             Esta ayuda
  -v, --version          Versión

Códigos de salida: 0 sin problemas graves · 1 hay problemas o señales de
phishing · 2 error (o no se pudo comprobar todo)

Ejemplos:
  $0 dominio miempresa.com.pa
  $0 dominio miempresa.com.pa --selector s2024 --format json -o informe.json
  $0 analizar sospechoso.eml --mi-dominio miempresa.com.pa
EOF
}

die() { printf 'Error: %s\n' "$1" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

sev_num() {
    case "$1" in critical) echo 4 ;; high) echo 3 ;; medium) echo 2 ;; low) echo 1 ;; *) echo 0 ;; esac
}
sev_label() {
    case "$1" in critical) echo "CRÍTICO" ;; high) echo "ALTO" ;; medium) echo "MEDIO" ;; low) echo "BAJO" ;; *) echo "INFO" ;; esac
}
setup_colors() {
    [[ -t 1 && -z "$OUTPUT_FILE" ]] || USE_COLOR=0
    if [[ $USE_COLOR -eq 1 ]]; then
        C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'
        C_MAG=$'\e[35m'; C_GRY=$'\e[90m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
    fi
}
# Etiqueta [ALTO] alineada (CRÍTICO lleva tilde: 2 bytes, la columna se corrige)
sev_tag() { local l; l="[$(sev_label "$1")]"; if [[ "$l" == *Í* ]]; then printf '%-10s' "$l"; else printf '%-9s' "$l"; fi; }
sev_color() {
    case "$1" in critical) printf '%s' "$C_MAG" ;; high) printf '%s' "$C_RED" ;;
                 medium) printf '%s' "$C_YEL" ;; *) printf '%s' "$C_BLU" ;; esac
}

# Texto que viene de fuera (DNS, correos): sin caracteres de control. Un
# registro DNS o un asunto con secuencias de escape no debe poder manipular
# la terminal de quien lee el informe.
clean() {
    local t
    t=$(printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037\177' | tr '\t\n\r' '   ')
    [[ "$t" == *[$'\x80'-$'\xff']* ]] || { printf '%s' "$t"; return; }
    # Bytes no ASCII: UTF-8 válido, sin controles C1 y sin caracteres que dan la vuelta al texto
    have iconv && t=$(printf '%s' "$t" | iconv -f UTF-8 -t UTF-8 -c 2>/dev/null)
    printf '%s' "$t" | sed -e 's/\xc2[\x80-\x9f]/ /g' -e 's/\xe2\x80[\xaa-\xae\x8e\x8f]/<RTLO>/g' -e 's/\xe2\x81[\xa6-\xa9]/<RTLO>/g' -e 's/\xd8\x9c/<RTLO>/g'
}

json_esc() {
    local s
    s=$(clean "$1")
    s=${s//\\/\\\\}; s=${s//\"/\\\"}
    printf '%s' "$s"
}

# Un dominio solo puede tener letras, números, guiones y puntos (y xn-- para
# los internacionalizados). Se valida antes de usarlo en una consulta DNS.
valid_domain() {
    local d=$1
    [[ ${#d} -le 253 && "$d" =~ ^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]
}
norm_domain() {
    local d=${1,,}
    d=${d##*@}          # admite "usuario@dominio"
    d=${d%.}
    printf '%s' "$d"
}

# =============================================================================
#  DNS
#  dns_query TIPO NOMBRE  →  DNS_STATUS (NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT...)
#                            DNS_ANS (una respuesta por elemento)
#  Distinguir "no existe" de "no se pudo consultar" es clave: un fallo de red
#  NUNCA debe convertirse en "tu dominio no tiene DMARC".
# =============================================================================
DNS_STATUS=""; DNS_ANS=()
DNS_COUNT=0
readonly DNS_LIMIT=120
declare -A DNS_CACHE_S=() DNS_CACHE_A=()

read -r -d '' DIG_AWK <<'AWK' || true  # read -d '' devuelve 1 al llegar al final: es normal
# Une los fragmentos de un TXT ("parte1" "parte2") y quita el escapado de dig
function txtjoin(s,    out, i, n, c, d, inq, v) {
    out = ""; n = length(s); inq = 0
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\\" && i < n) {
            d = substr(s, i + 1, 1)
            if (d ~ /[0-9]/ && i + 3 <= n) { v = substr(s, i + 1, 3) + 0; if (inq) out = out ((v < 32 || v == 127) ? "?" : sprintf("%c", v)); i += 3 }
            else { if (inq) out = out d; i++ }
            continue
        }
        if (c == "\"") { inq = !inq; continue }
        if (inq) out = out c
    }
    return out
}
/^;/ || NF < 5 { next }
toupper($4) == t {
    line = $0
    for (i = 1; i <= 4; i++) sub(/^[ \t]*[^ \t]+[ \t]+/, "", line)
    if (t == "TXT") line = txtjoin(line)
    gsub(/[\001-\037\177]/, "?", line)
    print line
}
AWK

dns_dig() {
    # -r: sin ~/.digrc (un "+short" ahí haría que todo pareciera un fallo de red)
    local type=$1 name=$2 out st args=(-r +noall +comments +answer +time=3 +tries=2)
    [[ -n "$RESOLVER" ]] && args+=("@$RESOLVER")
    out=$(dig "${args[@]}" -t "$type" -q "$name" 2>/dev/null)
    st=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<< "$out" | head -n1)
    if [[ -z "$st" ]]; then      # sin respuesta por UDP: se reintenta por TCP
        out=$(dig "${args[@]}" +tcp -t "$type" -q "$name" 2>/dev/null)
        st=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<< "$out" | head -n1)
    fi
    [[ -n "$st" ]] || { echo TIMEOUT; return 0; }
    echo "$st"
    awk -v t="$type" "$DIG_AWK" <<< "$out"
}

# Archivo de pruebas: "nombre TIPO dato" por línea; "nombre STATUS SERVFAIL"
# fuerza un error. Un nombre que no aparece se responde como NXDOMAIN.
dns_mock() {
    awk -v t="$1" -v n="$2" '
        /^[ \t]*(#|$)/ { next }
        { nm = tolower($1); sub(/\.$/, "", nm); if (nm != n) next
          if (toupper($2) == "STATUS") { if ($3 ~ /^[A-Z]+$/) forced = $3; next }
          found = 1
          if (toupper($2) != t) next
          v = $0; sub(/^[ \t]*[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", v); ans[++k] = v }
        END { st = forced != "" ? forced : (found ? "NOERROR" : "NXDOMAIN")
              print st; if (st == "NOERROR") for (i = 1; i <= k; i++) print ans[i] }' "$DNS_FILE"
}

dns_query() {
    local type=$1 name key raw
    name=$(norm_domain "$2")
    key="$type $name"
    DNS_ANS=()
    if [[ -n "${DNS_CACHE_S[$key]+x}" ]]; then
        DNS_STATUS=${DNS_CACHE_S[$key]}
        [[ -n "${DNS_CACHE_A[$key]}" ]] && mapfile -t DNS_ANS <<< "${DNS_CACHE_A[$key]}"
        return 0
    fi
    if (( DNS_COUNT >= DNS_LIMIT )); then DNS_STATUS=LIMIT; return 0; fi
    DNS_COUNT=$((DNS_COUNT + 1))
    if [[ -n "$DNS_FILE" ]]; then raw=$(dns_mock "$type" "$name")
    else raw=$(dns_dig "$type" "$name"); fi
    DNS_STATUS=${raw%%$'\n'*}
    [[ "$raw" == *$'\n'* ]] && mapfile -t DNS_ANS <<< "${raw#*$'\n'}"
    DNS_CACHE_S[$key]=$DNS_STATUS
    DNS_CACHE_A[$key]=""
    [[ ${#DNS_ANS[@]} -gt 0 ]] && DNS_CACHE_A[$key]=$(printf '%s\n' "${DNS_ANS[@]}")
    return 0
}

# Política MTA-STS por HTTPS (solo lectura, máx. 64 KB, 6 segundos)
https_get() {
    local host=$1
    if [[ -n "$DNS_FILE" ]]; then
        awk -v n="$host" 'tolower($1) == n && toupper($2) == "HTTPS" { v = $0; sub(/^[ \t]*[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", v); gsub(/\|/, "\n", v); print v; f = 1 } END { exit !f }' "$DNS_FILE"
        return
    fi
    have curl || return 99
    local out rc
    out=$(curl -q -fsS --max-time 6 --proto '=https' --max-filesize 65536 --max-redirs 0 \
        "https://$host/.well-known/mta-sts.txt" 2>/dev/null); rc=$?
    printf '%s' "${out:0:65536}"
    return $rc
}

# =============================================================================
#  Revisión de un dominio
# =============================================================================
F_SEV=(); F_ID=(); F_TXT=(); F_FIX=()
OKS=(); INCOMPLETE=()
add_f() { F_SEV+=("$1"); F_ID+=("$2"); F_TXT+=("$3"); F_FIX+=("${4:-}"); }
add_ok() { OKS+=("$1"); }
add_inc() { INCOMPLETE+=("$1"); }

D=""            # dominio revisado
MX_LIST=(); MX_NULL=0; PROVIDER=""; PROVIDER_ID=""
SPF_REC=""; SPF_STATE=""; SPF_ALL=""; SPF_LOOKUPS=0; SPF_VOID=0; SPF_PTR=0; SPF_MACRO=0; SPF_ERRS=(); SPF_WIDE=()
DM_REC=""; DM_STATE=""; DM_FROM=""; DM_EFF=""; declare -A DM=()
DK_FOUND=()
STS_STATE=""; STS_MODE=""; TLSRPT=""; DNSSEC=""

reset_domain_state() {
    F_SEV=(); F_ID=(); F_TXT=(); F_FIX=(); OKS=(); INCOMPLETE=()
    MX_LIST=(); MX_NULL=0; PROVIDER=""; PROVIDER_ID=""
    SPF_REC=""; SPF_STATE=""; SPF_ALL=""; SPF_LOOKUPS=0; SPF_VOID=0; SPF_PTR=0; SPF_MACRO=0; SPF_ERRS=(); SPF_WIDE=()
    DM_REC=""; DM_STATE=""; DM_FROM=""; DM_EFF=""; DM=()
    DK_FOUND=()
    STS_STATE=""; STS_MODE=""; TLSRPT=""; DNSSEC=""
}

# --- MX y proveedor -------------------------------------------------------------
check_mx() {
    local r host
    dns_query MX "$D"
    case "$DNS_STATUS" in
        NOERROR|NXDOMAIN) ;;
        *) add_inc "MX ($DNS_STATUS)"; return ;;
    esac
    for r in "${DNS_ANS[@]}"; do
        [[ -z "$r" ]] && continue
        MX_LIST+=("$r")
        host=${r#* }; host=${host,,}; host=${host%.}
        [[ "$r" =~ ^0[[:space:]]+\.?$ ]] && MX_NULL=1
        if [[ -z "$PROVIDER" ]]; then
            case "$host" in
                *.protection.outlook.com) PROVIDER="Microsoft 365"; PROVIDER_ID=m365 ;;
                gmail-smtp-in.l.google.com) PROVIDER="Gmail (correo gratuito de Google)"; PROVIDER_ID=gconsumer ;;
                *google.com|*googlemail.com) PROVIDER="Google Workspace"; PROVIDER_ID=google ;;
                *.zoho.com|*.zoho.eu|*.zohomail.com) PROVIDER="Zoho Mail"; PROVIDER_ID=zoho ;;
                *.secureserver.net) PROVIDER="GoDaddy"; PROVIDER_ID=godaddy ;;
                *.pphosted.com|*.ppe-hosted.com) PROVIDER="Proofpoint"; PROVIDER_ID=other ;;
                *.mimecast.com) PROVIDER="Mimecast"; PROVIDER_ID=other ;;
                *.barracudanetworks.com) PROVIDER="Barracuda"; PROVIDER_ID=other ;;
                *.hostinger.com) PROVIDER="Hostinger"; PROVIDER_ID=other ;;
            esac
        fi
    done
    if [[ $MX_NULL -eq 1 ]]; then
        PROVIDER="ninguno (MX nulo: el dominio declara que no usa correo)"; PROVIDER_ID=none
    elif [[ ${#MX_LIST[@]} -eq 0 ]]; then
        PROVIDER="ninguno (sin registros MX)"; PROVIDER_ID=none
    elif [[ -z "$PROVIDER" ]]; then
        PROVIDER="servidor propio u otro proveedor"; PROVIDER_ID=other
    fi
}

# ¿Quién gestiona el DNS? Es donde hay que hacer los cambios
NS_LIST=(); DNS_PANEL=""
check_ns() {
    local n=$D r
    NS_LIST=(); DNS_PANEL=""
    while :; do
        dns_query NS "$n"
        [[ "$DNS_STATUS" == NOERROR && ${#DNS_ANS[@]} -gt 0 ]] && break
        [[ "$n" == *.*.* ]] || return 0
        n=${n#*.}
    done
    for r in "${DNS_ANS[@]:0:4}"; do NS_LIST+=("${r%.}"); done
    case "${NS_LIST[0],,}" in
        *cloudflare.com) DNS_PANEL="Cloudflare (dash.cloudflare.com > tu dominio > DNS)" ;;
        *domaincontrol.com) DNS_PANEL="GoDaddy (Mis productos > DNS)" ;;
        *registrar-servers.com) DNS_PANEL="Namecheap (Domain List > Manage > Advanced DNS)" ;;
        *azure-dns.*) DNS_PANEL="Azure DNS" ;;
        *awsdns*) DNS_PANEL="Amazon Route 53" ;;
        *googledomains.com|*ns-cloud*) DNS_PANEL="Google Cloud DNS / Squarespace" ;;
        *hostinger*|*dns-parking.com) DNS_PANEL="Hostinger (hPanel > Dominios > DNS)" ;;
        *) DNS_PANEL="${NS_LIST[*]} (pregunta a tu proveedor de hosting o a quien registró el dominio; si usas cPanel: Zone Editor)" ;;
    esac
}

# Servidores de correo que no existen: el correo no llega, y si el dominio del
# servidor está libre, alguien podría registrarlo y recibir tu correo
check_mx_hosts() {
    local r host dead=0 total=0 rd
    [[ "$PROVIDER_ID" == none ]] && return 0
    for r in "${MX_LIST[@]:0:5}"; do
        host=${r#* }; host=${host,,}; host=${host%.}
        [[ -z "$host" || "$host" == . ]] && continue
        total=$((total + 1))
        dns_query A "$host"; local a=$DNS_STATUS na=${#DNS_ANS[@]}
        [[ "$a" == NOERROR && $na -gt 0 ]] && continue
        dns_query AAAA "$host"
        [[ "$DNS_STATUS" == NOERROR && ${#DNS_ANS[@]} -gt 0 ]] && continue
        [[ "$a" != NXDOMAIN && "$a" != NOERROR ]] && { add_inc "MX $host ($a)"; continue; }
        dead=$((dead + 1))
        rd=$(awk -F. '{ n = NF; if (n >= 3 && length($n) == 2 && $(n-1) ~ /^(com|net|org|gob|edu|co)$/) print $(n-2) "." $(n-1) "." $n; else print $(n-1) "." $n }' <<< "$host")
        dns_query SOA "$rd"
        if [[ "$DNS_STATUS" == NXDOMAIN ]]; then
            add_f critical MX-TAKEOVER "El servidor de correo $host pertenece a un dominio ($rd) que no existe: alguien podría registrarlo y recibir tu correo" \
                  "Corrige el registro MX con el servidor real de tu proveedor de correo"
        fi
    done
    if (( total > 0 && dead == total )); then
        add_f high MX-DEAD "Ningún servidor de correo (MX) existe: los correos que te envíen no llegan" "Corrige los registros MX con los que te indique tu proveedor de correo"
    elif (( dead > 0 )); then
        add_f medium MX-DEAD "$dead de $total servidores de correo (MX) no existen" "Quita o corrige los MX que ya no existen"
    fi
}

# --- SPF (RFC 7208) ---------------------------------------------------------------
# spf_get NOMBRE → SPF_GET (ok|none|multi|nx|dnserr) y SPF_GOT (el registro)
SPF_GET=""; SPF_GOT=""
spf_get() {
    local r n=0
    SPF_GOT=""
    dns_query TXT "$1"
    case "$DNS_STATUS" in
        NOERROR) ;;
        NXDOMAIN) SPF_GET=nx; return ;;
        *) SPF_GET=dnserr; return ;;
    esac
    for r in "${DNS_ANS[@]}"; do
        if [[ "${r,,}" =~ ^v=spf1([[:space:]]|$) ]]; then n=$((n + 1)); SPF_GOT=$r; fi
    done
    if (( n == 0 )); then SPF_GET=none; elif (( n > 1 )); then SPF_GET=multi; else SPF_GET=ok; fi
}

# Recorre un registro SPF contando las consultas DNS que provoca (máximo 10)
spf_walk() {
    local rec=$1 depth=$2 top=$3 term q mech arg terms
    read -r -a terms <<< "$rec"
    for term in "${terms[@]}"; do
        [[ "${term,,}" == v=spf1 ]] && continue
        q="+"
        case "$term" in [-+~?]*) q=${term:0:1}; term=${term:1} ;; esac
        mech=${term%%[:/=]*}; mech=${mech,,}
        arg=""
        [[ "$term" == *[:=]* ]] && arg=${term#*[:=]}
        case "$mech" in
            all)      if [[ $top -eq 1 ]]; then SPF_ALL=$q
                      elif [[ "$q" == "+" ]]; then SPF_WIDE+=("+all dentro de un include"); fi ;;
            include)  SPF_LOOKUPS=$((SPF_LOOKUPS + 1)); spf_follow "$arg" "$depth" include 0 ;;
            redirect) SPF_LOOKUPS=$((SPF_LOOKUPS + 1))
                      # redirect solo se usa si no hay "all"
                      if [[ $top -eq 1 && ! "${rec,,}" =~ (^|[[:space:]])[-+~?]?all([[:space:]]|$) ]]; then
                          spf_follow "$arg" "$depth" redirect 1
                      else
                          spf_follow "$arg" "$depth" redirect 0
                      fi ;;
            a|mx|exists) SPF_LOOKUPS=$((SPF_LOOKUPS + 1)) ;;
            ptr)      SPF_LOOKUPS=$((SPF_LOOKUPS + 1)); SPF_PTR=1 ;;
            ip4|ip6)  if [[ -n "$arg" && "$arg" =~ ^[0-9A-Fa-f:.]+(/([0-9]{1,3}))?$ ]]; then
                          # Rangos enormes autorizan a medio internet (ip4:0.0.0.0/1)
                          local pfx=${BASH_REMATCH[2]:-}
                          if [[ -n "$pfx" && "$q" != "-" ]] && { [[ "$mech" == ip4 ]] && (( 10#$pfx < 16 )) || { [[ "$mech" == ip6 ]] && (( 10#$pfx < 32 )); }; }; then
                              SPF_WIDE+=("$(clean "$term")")
                          fi
                      else SPF_ERRS+=("dirección no válida en '$(clean "$term")'"); fi ;;
            exp)      ;;
            *)        if [[ "$term" == *=* ]]; then :   # modificador desconocido: se ignora (RFC 7208)
                      else SPF_ERRS+=("mecanismo desconocido '$(clean "$term")'"); fi ;;
        esac
    done
}

spf_follow() {
    local name=$1 depth=$2 kind=$3 top=$4 got
    if [[ "$name" == *%* ]]; then SPF_MACRO=1; return; fi    # macros: dependen de cada correo
    name=$(norm_domain "$name")
    if ! valid_domain "$name"; then SPF_ERRS+=("destino no válido en $kind: '$(clean "$name")'"); return; fi
    # Un include repetido cuenta otra vez (RFC 7208 §4.6.4); los bucles se cortan
    # al superar el límite de 10 consultas o la profundidad máxima
    (( SPF_LOOKUPS > 10 || depth >= 10 )) && return
    spf_get "$name"
    case "$SPF_GET" in
        ok)     got=$SPF_GOT; spf_walk "$got" $((depth + 1)) "$top" ;;
        nx)     SPF_VOID=$((SPF_VOID + 1))
                SPF_ERRS+=("'$name' ($kind) no existe: los receptores darán error (permerror)") ;;
        none)   SPF_VOID=$((SPF_VOID + 1))
                SPF_ERRS+=("'$name' ($kind) no tiene registro SPF: los receptores darán error (permerror)") ;;
        multi)  SPF_ERRS+=("'$name' ($kind) tiene varios registros SPF (permerror)") ;;
        dnserr) add_inc "SPF de $name ($DNS_STATUS)" ;;
    esac
}

spf_suggest() {
    case "$PROVIDER_ID" in
        google) printf 'v=spf1 include:_spf.google.com ~all' ;;
        m365)   printf 'v=spf1 include:spf.protection.outlook.com -all' ;;
        none)   printf 'v=spf1 -all' ;;
        *)      printf 'v=spf1 mx -all' ;;
    esac
}

check_spf() {
    local e
    spf_get "$D"
    SPF_STATE=$SPF_GET
    case "$SPF_GET" in
        dnserr) add_inc "SPF ($DNS_STATUS)"; return ;;
        nx|none)
            local extra=""
            [[ "$PROVIDER_ID" == other ]] && extra=" y añade un include: por cada servicio que envíe correo por ti (facturación electrónica, Mailchimp, la web)"
            add_f high SPF-NONE "No hay registro SPF: nadie sabe qué servidores pueden enviar correo como @$D" \
                  "Publica un TXT en $D con el valor: $(spf_suggest)$extra"
            return ;;
        multi)
            add_f high SPF-MULTI "Hay varios registros SPF: los receptores lo tratan como un error y el SPF no sirve" \
                  "Une todo en UN solo TXT que empiece por v=spf1"
            return ;;
    esac
    SPF_REC=$SPF_GOT
    spf_walk "$SPF_REC" 0 1

    if (( ${#SPF_REC} > 450 )); then
        add_f low SPF-LONG "El registro SPF es muy largo (${#SPF_REC} caracteres): algunos servidores no leen respuestas DNS grandes" \
              "Quita los include: que ya no uses"
    fi
    case "$SPF_ALL" in
        "+")  add_f critical SPF-PLUSALL "SPF termina en +all: autoriza a TODO internet a enviar correo como @$D" \
                    "Cambia +all por -all (o ~all si tienes DMARC en reject)" ;;
        "?")  add_f medium SPF-NEUTRAL "SPF termina en ?all (neutral): no dice nada sobre los servidores no autorizados" \
                    "Cambia ?all por -all o ~all" ;;
        "~")  add_ok "SPF publicado y termina en ~all" ;;
        "-")  add_ok "SPF publicado y termina en -all (estricto)" ;;
        "")   add_f medium SPF-NOALL "SPF sin \"all\" al final: el resultado para servidores no autorizados queda en neutral" \
                    "Añade -all (o ~all) al final del registro" ;;
    esac
    if (( SPF_LOOKUPS > 10 )); then
        add_f high SPF-LOOKUPS "SPF necesita más de 10 consultas DNS ($SPF_LOOKUPS): los receptores dan error y el SPF deja de funcionar" \
              "Quita include: que no uses o cambia algunos por ip4:/ip6:"
    elif (( SPF_LOOKUPS >= 8 )); then
        add_f low SPF-LOOKUPS-NEAR "SPF usa $SPF_LOOKUPS de las 10 consultas DNS permitidas: un include más y dejará de funcionar" \
              "Revisa qué servicios ya no envían correo por ti"
    fi
    (( SPF_VOID > 2 )) && add_f medium SPF-VOID "SPF tiene $SPF_VOID consultas vacías (máximo 2): los receptores pueden dar error" \
              "Quita los include: de dominios que ya no existen"
    (( SPF_PTR )) && add_f medium SPF-PTR "SPF usa el mecanismo ptr: está desaconsejado (lento y poco fiable) y algunos receptores lo ignoran" \
              "Sustituye ptr por ip4:/ip6: o include:"
    if [[ ${#SPF_WIDE[@]} -gt 0 ]]; then
        e=$(printf '%s, ' "${SPF_WIDE[@]:0:3}"); e=${e%, }
        add_f critical SPF-WIDE "El SPF autoriza rangos enormes de internet ($e): cualquiera con un servidor ahí pasa SPF y DMARC no lo frena" \
              "Cambia esos rangos por las IPs exactas de tus servidores (o el include: de tu proveedor)"
    fi
    if [[ ${#SPF_ERRS[@]} -gt 0 ]]; then
        e=$(printf '%s; ' "${SPF_ERRS[@]:0:5}"); e=${e%; }
        [[ ${#SPF_ERRS[@]} -gt 5 ]] && e+=" (y $(( ${#SPF_ERRS[@]} - 5 )) más)"
        add_f high SPF-ERROR "SPF con errores, así que los receptores pueden ignorarlo entero: $e" "Corrige el registro SPF"
    fi
}

# --- DMARC (RFC 9989) -------------------------------------------------------------
DM_GET=""; DM_GOT=""
dmarc_get() {
    local r n=0
    DM_GOT=""
    dns_query TXT "_dmarc.$1"
    case "$DNS_STATUS" in
        NOERROR) ;;
        NXDOMAIN) DM_GET=none; return ;;
        *) DM_GET=dnserr; return ;;
    esac
    for r in "${DNS_ANS[@]}"; do
        if [[ "$r" =~ ^[[:space:]]*v[[:space:]]*=[[:space:]]*DMARC1[[:space:]]*(;|$) ]]; then n=$((n + 1)); DM_GOT=$r; fi
    done
    if (( n == 0 )); then DM_GET=none; elif (( n > 1 )); then DM_GET=multi; else DM_GET=ok; fi
}

dmarc_parse() {
    local rec=$1 tag k v tags
    DM=()
    IFS=';' read -r -a tags <<< "$rec"
    for tag in "${tags[@]}"; do
        [[ "$tag" == *=* ]] || continue
        k=${tag%%=*}; v=${tag#*=}
        k=${k//[[:space:]]/}; k=${k,,}
        v=${v#"${v%%[![:space:]]*}"}; v=${v%"${v##*[![:space:]]}"}
        [[ -n "$k" && -z "${DM[$k]+x}" ]] && DM[$k]=$v
    done
}

check_dmarc() {
    local name=$D parent tries=0 p sp np pct t
    dmarc_get "$name"
    # Si un subdominio no tiene DMARC propio, se usa el de su dominio "padre"
    # (búsqueda por el árbol DNS de RFC 9989, máximo 8 consultas)
    while [[ "$DM_GET" == none && "$name" == *.*.* && $tries -lt 7 ]]; do
        parent=${name#*.}
        tries=$((tries + 1))
        dmarc_get "$parent"
        name=$parent
        [[ "$DM_GET" != none ]] && DM_FROM=$parent
    done
    DM_STATE=$DM_GET
    case "$DM_GET" in
        dnserr) add_inc "DMARC ($DNS_STATUS)"; return ;;
        none)
            add_f high DMARC-NONE "No hay política DMARC: cualquiera puede enviar correos haciéndose pasar por @$D y llegarán a la bandeja de entrada" \
                  "Publica un TXT en _dmarc.$D: \"v=DMARC1; p=none; rua=mailto:dmarc@$D\" y, tras revisar los informes 2-4 semanas, sube a p=quarantine y luego p=reject"
            return ;;
        multi)
            add_f high DMARC-MULTI "Hay varios registros DMARC: los receptores los ignoran todos" \
                  "Deja UN solo TXT en _dmarc.$D"
            return ;;
    esac
    DM_REC=$DM_GOT
    dmarc_parse "$DM_REC"
    p=${DM[p]:-}; p=${p,,}; sp=${DM[sp]:-}; sp=${sp,,}; np=${DM[np]:-}; np=${np,,}
    # Política que se aplica de verdad: un subdominio que hereda el DMARC de su
    # dominio principal usa sp= si existe
    local pol=$p
    [[ -n "$DM_FROM" && -n "$sp" ]] && pol=$sp
    [[ -n "$DM_FROM" ]] && add_ok "DMARC heredado del dominio principal $DM_FROM"
    if [[ "$pol" != none && "$pol" != quarantine && "$pol" != reject ]]; then
        add_f medium DMARC-SYNTAX "DMARC sin una política p= válida: los receptores la tratan como p=none (no protege)" \
              "Corrige el registro: \"v=DMARC1; p=quarantine; rua=mailto:dmarc@$D\""
        pol=none
    fi
    local pctv=${DM[pct]:-100}
    if [[ "$pctv" =~ ^[0-9]+$ ]] && (( pctv == 0 )) && [[ "$pol" != none ]]; then
        add_f medium DMARC-PCT0 "pct=0: la política $pol no se aplica a ningún correo, así que en la práctica no protege" "Quita pct=0"
        pol=none
    fi
    DM_EFF=$pol
    case "$pol" in
        reject)
            add_ok "DMARC en p=reject: los correos falsos con tu dominio se rechazan" ;;
        quarantine)
            add_f low DMARC-QUARANTINE "DMARC en p=quarantine: los correos falsos van a spam (todavía llegan al buzón)" \
                  "Cuando los informes muestren que todo tu correo legítimo pasa, sube a p=reject" ;;
        none)
            if [[ -n "$DM_FROM" && "$sp" == none ]]; then
                add_f high DMARC-P-NONE "Este subdominio hereda sp=none de $DM_FROM: NO está protegido" \
                      "Pon sp=reject en _dmarc.$DM_FROM o publica un DMARC propio en _dmarc.$D"
            elif ! printf '%s\n' "${F_ID[@]}" | grep -q '^DMARC-\(SYNTAX\|PCT0\)$'; then
                if [[ -n "${DM[rua]:-}" ]]; then
                    add_f high DMARC-P-NONE "DMARC en p=none: solo observa, NO protege. Los correos falsos siguen llegando" \
                          "Revisa los informes (rua) 2-4 semanas y sube a p=quarantine; después a p=reject"
                else
                    add_f high DMARC-P-NONE "DMARC en p=none y sin informes: ni protege ni te enteras de nada" \
                          "Pon p=quarantine si ya sabes qué servicios envían por ti; si no, añade rua= para ver informes y sube en 2-4 semanas"
                fi
            fi ;;
    esac
    if [[ -z "$DM_FROM" && ( "$pol" == quarantine || "$pol" == reject ) ]]; then
        [[ "$sp" == none ]] && add_f medium DMARC-SP-NONE "sp=none: los subdominios (ventas.$D, pagos.$D...) se pueden suplantar aunque el dominio esté protegido" \
                  "Quita sp=none o pon sp=reject"
        [[ "$np" == none ]] && add_f low DMARC-NP-NONE "np=none: subdominios que ni siquiera existen se pueden usar para suplantarte" \
                  "Quita np=none o pon np=reject"
    fi
    pct=${DM[pct]:-100}
    if [[ "$pct" =~ ^[0-9]+$ ]] && (( pct > 0 && pct < 100 )); then
        add_f low DMARC-PCT "pct=$pct: la política solo se aplica a una parte del correo. Además, pct ya no existe en el estándar actual (RFC 9989)" \
              "Quita pct=$pct"
    fi
    t=${DM[t]:-}
    [[ "${t,,}" == y ]] && add_f low DMARC-TESTING "t=y: DMARC en modo de prueba, los receptores aplican una política más suave" \
              "Quita t=y cuando termines las pruebas"
    if [[ -z "${DM[rua]:-}" && "$PROVIDER_ID" == none ]]; then
        :   # un dominio sin correo no necesita informes
    elif [[ -n "${DM[rua]:-}" ]]; then
        check_rua "${DM[rua]}"
    elif [[ -z "${DM[rua]:-}" ]]; then
        add_f low DMARC-NORUA "DMARC sin rua: no recibes informes, así que no sabes quién envía correo con tu nombre" \
              "Añade rua=mailto: con un buzón que alguien revise, o con un servicio gratuito de informes DMARC (Postmark DMARC Digests, Cloudflare DMARC Management): los informes son XML en inglés y estos servicios los resumen"
    fi
}

# Destinos de los informes DMARC: deben ser mailto:, y si son de otro dominio,
# ese dominio tiene que aceptarlos publicando un registro (si no, se descartan)
check_rua() {
    local list=$1 u addr dom org mine rr ok
    mine=$(awk -F. '{ n = NF; if (n >= 3 && length($n) == 2 && $(n-1) ~ /^(com|net|org|gob|edu|co)$/) print $(n-2) "." $(n-1) "." $n; else print $(n-1) "." $n }' <<< "${DM_FROM:-$D}")
    IFS=, read -r -a _ruas <<< "$list"
    for u in "${_ruas[@]:0:5}"; do
        u=${u//[[:space:]]/}
        if [[ "${u,,}" != mailto:* ]]; then
            add_f low DMARC-RUA-BAD "El destino de informes \"$(clean "$u")\" no empieza por mailto:, así que no recibirás nada" "Escríbelo así: rua=mailto:direccion@dominio"
            continue
        fi
        addr=${u#*:}; addr=${addr%%!*}; dom=${addr##*@}; dom=${dom,,}
        valid_domain "$dom" || continue
        org=$(awk -F. '{ n = NF; if (n >= 3 && length($n) == 2 && $(n-1) ~ /^(com|net|org|gob|edu|co)$/) print $(n-2) "." $(n-1) "." $n; else print $(n-1) "." $n }' <<< "$dom")
        [[ "$org" == "$mine" ]] && continue
        dns_query TXT "${DM_FROM:-$D}._report._dmarc.$dom"
        case "$DNS_STATUS" in
            NOERROR|NXDOMAIN) ok=0; for rr in "${DNS_ANS[@]}"; do [[ "$rr" == v=DMARC1* ]] && ok=1; done
                (( ok )) || add_f low DMARC-RUA-AUTH "Los informes van a $dom, pero ese dominio no ha autorizado recibirlos: se pierden" \
                    "Pide al servicio de informes que publique ${DM_FROM:-$D}._report._dmarc.$dom, o usa un buzón de tu propio dominio" ;;
            *) add_inc "autorización de informes DMARC ($DNS_STATUS)" ;;
        esac
    done
    add_ok "DMARC envía informes (rua): puedes ver quién usa tu dominio"
}

# --- DKIM (RFC 6376) -----------------------------------------------------------------
# El selector no se puede descubrir por DNS: se prueban los más habituales.
DKIM_DEFAULT=(google selector1 selector2 default k1 k2 s1 s2 dkim mail smtp zoho zmail mxvault mandrill everlytickey1 hs1 hs2 protonmail sig1 20230601 20221208 20161025)

dkim_bits() {
    local p=$1 k=$2 bits="" n
    [[ "${k,,}" == ed25519 ]] && { echo ed25519; return; }
    [[ "$p" =~ ^[A-Za-z0-9+/=]+$ ]] || { echo "?"; return; }
    if have openssl; then
        bits=$( { printf -- '-----BEGIN PUBLIC KEY-----\n'; fold -w 64 <<< "$p"; printf -- '-----END PUBLIC KEY-----\n'; } \
                | openssl pkey -pubin -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -n1)
    fi
    if [[ -z "$bits" ]]; then       # aproximación por el tamaño de la llave
        n=${#p}
        if (( n < 150 )); then bits="~512"; elif (( n < 300 )); then bits="~1024"; elif (( n < 500 )); then bits="~2048"; else bits="~4096"; fi
    fi
    echo "$bits"
}

check_dkim() {
    local sel r p k t bits sels=() found=0 errs=0 tested=0 weak=""
    if [[ ${#SELECTORS[@]} -gt 0 ]]; then sels=("${SELECTORS[@]}"); else sels=("${DKIM_DEFAULT[@]}"); fi
    for sel in "${sels[@]}"; do
        tested=$((tested + 1))
        dns_query TXT "$sel._domainkey.$D"
        case "$DNS_STATUS" in
            NOERROR|NXDOMAIN) ;;
            *) errs=$((errs + 1)); continue ;;
        esac
        for r in "${DNS_ANS[@]}"; do
            [[ "$r" =~ (^|;)[[:space:]]*p[[:space:]]*= ]] || continue
            [[ "$r" =~ v[[:space:]]*=[[:space:]]*DKIM1 || "$r" =~ k[[:space:]]*= ]] || continue
            p=$(sed -n 's/.*\(^\|;\)[[:space:]]*p[[:space:]]*=[[:space:]]*\([^;]*\).*/\2/p' <<< "$r"); p=${p//[[:space:]]/}
            k=$(sed -n 's/.*\(^\|;\)[[:space:]]*k[[:space:]]*=[[:space:]]*\([^;]*\).*/\2/p' <<< "$r"); k=${k//[[:space:]]/}
            t=$(sed -n 's/.*\(^\|;\)[[:space:]]*t[[:space:]]*=[[:space:]]*\([^;]*\).*/\2/p' <<< "$r"); t=${t//[[:space:]]/}
            if [[ -z "$p" ]]; then
                DK_FOUND+=("$sel|revocada|$t"); continue
            fi
            bits=$(dkim_bits "$p" "${k:-rsa}")
            DK_FOUND+=("$sel|$bits|$t")
            found=$((found + 1))
            [[ "$bits" =~ ^~?(512|1024)$ ]] && weak+="${weak:+, }$sel ($bits bits)"
            [[ "$t" == *y* ]] && add_f low DKIM-TESTING "La llave DKIM '$sel' está en modo de prueba (t=y)" "Quita t=y del registro"
            break
        done
    done
    if (( found > 0 )); then
        add_ok "DKIM publicado (selector: $(for r in "${DK_FOUND[@]}"; do [[ "$r" == *"|revocada|"* ]] || printf '%s ' "${r%%|*}"; done | sed 's/ $//'))"
        [[ -n "$weak" ]] && add_f low DKIM-WEAK "Llave DKIM corta: $weak. Hoy se recomienda 2048 bits" \
              "Genera una llave nueva de 2048 bits en tu proveedor de correo y publica el nuevo selector"
    elif (( errs > 0 )); then
        add_inc "DKIM ($errs selector(es) sin respuesta del DNS)"
    elif [[ "$PROVIDER_ID" != none && "$PROVIDER_ID" != gconsumer ]]; then
        local how="activa DKIM en tu proveedor de correo y publica el registro que te indique"
        case "$PROVIDER_ID" in
            m365)   how="actívalo en security.microsoft.com/authentication (pestaña DKIM) y publica los dos CNAME selector1 y selector2 que te indica" ;;
            google) how="actívalo en admin.google.com > Aplicaciones > Google Workspace > Gmail > Autenticar correo electrónico, y publica el TXT google._domainkey que te da" ;;
        esac
        add_f medium DKIM-NOTFOUND "No se encontró DKIM con los selectores habituales: sin DKIM, tus correos son más fáciles de imitar y de mandar a spam" \
              "Si ya usas DKIM con otro selector, indícalo con --selector NOMBRE. Si no: $how"
    fi
}

# --- Transporte: MTA-STS, TLS-RPT, DNSSEC -----------------------------------------
check_transport() {
    local r pol mode="" rc=0 pt
    [[ "$PROVIDER_ID" == none ]] && return 0
    dns_query TXT "_mta-sts.$D"
    case "$DNS_STATUS" in
        NOERROR|NXDOMAIN)
            for r in "${DNS_ANS[@]}"; do [[ "$r" =~ ^v=STSv1 ]] && STS_STATE=dns; done ;;
        *) add_inc "MTA-STS ($DNS_STATUS)" ;;
    esac
    if [[ "$STS_STATE" == dns ]]; then
        if [[ $NO_HTTPS -eq 1 ]]; then
            STS_STATE=dns-only
        elif pol=$(https_get "mta-sts.$D"); rc=$?; [[ $rc -eq 0 && -n "$pol" ]]; then
            mode=$(sed -n 's/^mode:[[:space:]]*\([a-z]*\).*/\1/p' <<< "$pol" | tr -d '\r' | head -n1)
            STS_MODE=$mode; STS_STATE=ok
            # Cada MX debe aparecer en la política; si no, los que respetan MTA-STS no entregan
            local pats r2 h2 okm bad=""
            pats=$(sed -n 's/^mx:[[:space:]]*\([^[:space:]]*\).*/\1/p' <<< "$pol" | tr -d '\r' | tr '[:upper:]' '[:lower:]')
            for r2 in "${MX_LIST[@]:0:5}"; do
                h2=${r2#* }; h2=${h2,,}; h2=${h2%.}; okm=0
                while IFS= read -r pt; do
                    [[ -z "$pt" ]] && continue
                    if [[ "$pt" == \*.* ]]; then [[ "$h2" == *."${pt#\*.}" && "${h2%."${pt#\*.}"}" != *.* ]] && okm=1
                    elif [[ "$h2" == "$pt" ]]; then okm=1; fi
                done <<< "$pats"
                (( okm )) || bad+="${bad:+, }$h2"
            done
            if [[ -n "$bad" && "$mode" != none ]]; then
                add_f "$([[ "$mode" == enforce ]] && echo high || echo medium)" STS-MX-MISMATCH "La política MTA-STS no incluye estos servidores de correo: $bad. Gmail y Outlook pueden negarse a entregarte correo" \
                      "Añade una línea mx: por cada servidor en https://mta-sts.$D/.well-known/mta-sts.txt y cambia el id= del registro _mta-sts"
            fi
            case "$mode" in
                enforce) add_ok "MTA-STS en modo enforce: el correo que recibes viaja siempre cifrado" ;;
                testing) add_f low STS-TESTING "MTA-STS en modo testing: todavía no obliga a cifrar" "Cuando los informes TLS-RPT estén limpios, cambia a mode: enforce" ;;
                *)       add_f low STS-BAD "La política MTA-STS no tiene un modo válido" "Revisa https://mta-sts.$D/.well-known/mta-sts.txt" ;;
            esac
        else
            # ¿Fallo de la empresa (no existe, 404, certificado malo) o de nuestra red?
            dns_query A "mta-sts.$D"; local ast=$DNS_STATUS
            # Detrás de un proxy, un error HTTP puede ser del proxy y no de la empresa
            local via_proxy=0
            [[ -n "${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-}" ]] && via_proxy=1
            if [[ "$ast" == NXDOMAIN || ( "$ast" == NOERROR && ${#DNS_ANS[@]} -eq 0 ) || ( $via_proxy -eq 0 && ( $rc -eq 22 || $rc -eq 60 || $rc -eq 51 || $rc -eq 35 ) ) || ( $rc -eq 0 && -z "$pol" ) ]]; then
                STS_STATE=broken
                add_f medium STS-BROKEN "Hay registro MTA-STS pero la política de https://mta-sts.$D no se puede leer (no existe, da error o su certificado no es válido)" \
                      "Publica la política por HTTPS con un certificado válido, o quita el registro _mta-sts"
            else
                STS_STATE=dns-only
                add_inc "política MTA-STS (sin conexión HTTPS)"
            fi
        fi
    else
        STS_STATE=none
        add_f info STS-NONE "Sin MTA-STS: un atacante en la red podría forzar que el correo que recibes viaje sin cifrar" \
              "Opcional (recomendado): publica MTA-STS en modo testing y luego enforce"
    fi
    dns_query TXT "_smtp._tls.$D"
    case "$DNS_STATUS" in
        NOERROR|NXDOMAIN)
            TLSRPT=no
            for r in "${DNS_ANS[@]}"; do [[ "$r" =~ ^v=TLSRPTv1 ]] && TLSRPT=yes; done
            [[ $TLSRPT == yes ]] && add_ok "TLS-RPT publicado: recibes informes de problemas de cifrado" ;;
        *) add_inc "TLS-RPT ($DNS_STATUS)" ;;
    esac
}

check_dnssec() {
    dns_query DS "$D"
    case "$DNS_STATUS" in
        NOERROR)
            if [[ ${#DNS_ANS[@]} -gt 0 ]]; then
                DNSSEC=yes; add_ok "DNSSEC activo: las respuestas DNS del dominio están firmadas"
            else
                DNSSEC=no
                add_f info DNSSEC-NONE "Sin DNSSEC: las respuestas DNS del dominio no están firmadas" \
                      "Opcional: actívalo en tu registrador y en tu proveedor DNS"
            fi ;;
        NXDOMAIN) DNSSEC=no ;;
        *) DNSSEC="?" ;;
    esac
}

# Dominios que NO envían correo también se suplantan: hay que blindarlos
check_parked() {
    [[ "$PROVIDER_ID" == none ]] || return 0
    [[ "$SPF_STATE" == dnserr || "$DM_STATE" == dnserr ]] && return 0     # sin datos no se acusa
    if [[ "$SPF_ALL" != "-" || "$DM_EFF" != reject ]]; then
        add_f high PARKED-OPEN "Este dominio no recibe correo, pero se puede usar para enviar correos falsos" \
              "Blíndalo: TXT en $D \"v=spf1 -all\", TXT en _dmarc.$D \"v=DMARC1; p=reject;\" y MX nulo \"0 .\""
    else
        add_ok "Dominio sin correo y blindado contra suplantación (SPF -all y DMARC reject)"
    fi
}

# --- Nota -----------------------------------------------------------------------------
SCORE=0; GRADE=""; WORST=0
compute_grade() {
    local i s pts=0 p=$DM_EFF
    WORST=0
    for i in "${!F_SEV[@]}"; do
        s=${F_SEV[$i]}
        case "$s" in critical) pts=$((pts + 45)) ;; high) pts=$((pts + 25)) ;; medium) pts=$((pts + 10)) ;; low) pts=$((pts + 3)) ;; esac
        (( $(sev_num "$s") > WORST )) && WORST=$(sev_num "$s")
    done
    SCORE=$((100 - pts)); (( SCORE < 0 )) && SCORE=0
    if   (( SCORE >= 90 )); then GRADE=A
    elif (( SCORE >= 75 )); then GRADE=B
    elif (( SCORE >= 60 )); then GRADE=C
    elif (( SCORE >= 40 )); then GRADE=D
    else GRADE=F; fi
    # Sin DMARC que bloquee, el dominio se puede suplantar: no puede aprobar
    if [[ "$DM_STATE" != dnserr && "$p" != reject && "$p" != quarantine && "$GRADE" =~ ^[AB]$ ]]; then GRADE=C; fi
    # Sin poder leer SPF o DMARC no se puede poner nota
    [[ "$SPF_STATE" == dnserr || "$DM_STATE" == dnserr ]] && GRADE="?"
}

verdict_line() {
    local p=$DM_EFF
    if [[ "$DM_STATE" == dnserr ]]; then
        echo "No se pudo comprobar la política DMARC: repite la revisión más tarde."
    elif [[ "$PROVIDER_ID" == none ]]; then
        [[ "$SPF_ALL" == "-" && "$p" == reject ]] && echo "Dominio sin correo, protegido contra suplantación." \
            || echo "Dominio sin correo, pero se puede usar para enviar correos falsos."
    elif [[ "$p" == reject ]]; then echo "Los correos falsos que usen @$D son rechazados."
    elif [[ "$p" == quarantine ]]; then echo "Los correos falsos que usen @$D van a la carpeta de spam."
    else echo "Hoy cualquiera puede enviar correos que parezcan venir de @$D."
    fi
}

run_domain() {
    D=$(norm_domain "$1")
    valid_domain "$D" || die "dominio no válido: '$(clean "$1")'"
    reset_domain_state
    dns_query SOA "$D"
    case "$DNS_STATUS" in
        NOERROR) ;;
        NXDOMAIN) die "el dominio $D no existe" ;;
        *) die "no se pudo consultar el DNS ($DNS_STATUS). ¿Hay conexión a internet? Prueba con --resolver 1.1.1.1" ;;
    esac
    check_mx
    check_ns
    check_mx_hosts
    check_spf
    check_dmarc
    if [[ "$PROVIDER_ID" != none ]]; then check_dkim; fi
    check_transport
    check_dnssec
    check_parked
    compute_grade
}

# Orden de los hallazgos: más graves primero
sorted_findings() {
    local i
    for i in "${!F_SEV[@]}"; do printf '%s\t%s\n' "$((5 - $(sev_num "${F_SEV[$i]}")))" "$i"; done | sort -t$'\t' -k1,1n -k2,2n | cut -f2
}

render_domain_text() {
    local c=${1:-0} b="" x="" g="" y="" i col="" n=0 r sel bits t
    [[ $c -eq 1 ]] && { b=$C_BLD; x=$C_RST; g=$C_GRY; y=$C_GRN; }
    printf '%scorreo-escudo v%s%s — ¿se puede suplantar el correo de %s%s%s?\n' "$b" "$VERSION" "$x" "$b" "$D" "$x"
    printf '%sProveedor de correo: %s · %s%s\n' "$g" "$PROVIDER" "$(date '+%Y-%m-%d %H:%M')" "$x"
    [[ -n "$DNS_PANEL" ]] && printf '%sDNS gestionado en: %s%s\n' "$g" "$DNS_PANEL" "$x"
    local gc=$y
    [[ $c -eq 1 ]] && case "$GRADE" in C) gc=$C_YEL ;; D|F) gc=$C_RED ;; esac
    [[ $c -eq 1 ]] || gc=""
    printf '\n  Nota: %s%s%s (%d/100)   %s\n' "$gc$b" "$GRADE" "$x" "$SCORE" "$(verdict_line)"
    if [[ ${#INCOMPLETE[@]} -gt 0 ]]; then
        local inc w=""
        inc=$(printf '%s, ' "${INCOMPLETE[@]}"); inc=${inc%, }
        [[ $c -eq 1 ]] && w=$C_YEL
        printf '  %sATENCIÓN: no se pudo comprobar todo (%s). La nota puede no ser exacta.%s\n' "$w" "$inc" "$x"
    fi

    if [[ ${#OKS[@]} -gt 0 ]]; then
        printf '\n%s== Lo que está bien ==%s\n' "$b" "$x"
        for r in "${OKS[@]}"; do printf '  %s[OK]%s %s\n' "$y" "$x" "$r"; done
    fi

    printf '\n%s== Problemas encontrados ==%s\n' "$b" "$x"
    if [[ ${#F_SEV[@]} -eq 0 ]]; then
        printf '  %sNinguno.%s Configuración excelente.\n' "$y" "$x"
    else
        while IFS= read -r i; do
            [[ $c -eq 1 ]] && col=$(sev_color "${F_SEV[$i]}")
            printf '  %s%s%s %-17s %s\n' "$col" "$(sev_tag "${F_SEV[$i]}")" "$x" "${F_ID[$i]}" "${F_TXT[$i]}"
            [[ -n "${F_FIX[$i]}" ]] && printf '  %s%-9s %-17s Cómo arreglarlo: %s%s\n' "$g" "" "" "${F_FIX[$i]}" "$x"
        done < <(sorted_findings)
    fi

    printf '\n%s== Registros publicados ==%s\n' "$b" "$x"
    if [[ ${#MX_LIST[@]} -gt 0 ]]; then
        for r in "${MX_LIST[@]:0:5}"; do printf '  %-8s %s\n' "MX" "$(clean "$r")"; done
    else
        printf '  %-8s (ninguno)\n' "MX"
    fi
    if [[ -n "$SPF_REC" ]]; then printf '  %-8s %s\n' "SPF" "$(clean "$SPF_REC")"; else printf '  %-8s (ninguno)\n' "SPF"; fi
    [[ -n "$SPF_REC" ]] && printf '  %-8s %s%d de 10 consultas DNS%s%s\n' "" "$g" "$SPF_LOOKUPS" "$([[ $SPF_MACRO -eq 1 ]] && echo ' (usa macros: no se pueden contar del todo)')" "$x"
    if [[ -n "$DM_REC" ]]; then printf '  %-8s %s%s\n' "DMARC" "$(clean "$DM_REC")" "${DM_FROM:+   (de $DM_FROM)}"; else printf '  %-8s (ninguno)\n' "DMARC"; fi
    if [[ ${#DK_FOUND[@]} -gt 0 ]]; then
        for r in "${DK_FOUND[@]}"; do
            IFS='|' read -r sel bits t <<< "$r"
            if [[ "$bits" == revocada ]]; then printf '  %-8s %s (llave revocada)\n' "DKIM" "$sel"
            elif [[ "$bits" == ed25519 ]]; then printf '  %-8s %s (Ed25519)\n' "DKIM" "$sel"
            else printf '  %-8s %s (%s bits)\n' "DKIM" "$sel" "${bits#\~}"; fi
        done
    elif [[ "$PROVIDER_ID" != none ]]; then
        printf '  %-8s (no encontrado con %s)\n' "DKIM" "$([[ ${#SELECTORS[@]} -gt 0 ]] && echo "el selector indicado" || echo "los ${#DKIM_DEFAULT[@]} selectores habituales")"
    fi
    if [[ "$PROVIDER_ID" != none ]]; then
        printf '  %-8s %s\n' "MTA-STS" "$(case "$STS_STATE" in ok) echo "sí (modo $STS_MODE)" ;; dns-only) echo "registro DNS (política no comprobada)" ;; broken) echo "registro DNS, pero la política no se pudo leer" ;; *) echo "no" ;; esac)"
        printf '  %-8s %s\n' "TLS-RPT" "$([[ "$TLSRPT" == yes ]] && echo sí || echo no)"
    fi
    printf '  %-8s %s\n' "DNSSEC" "$(case "$DNSSEC" in yes) echo sí ;; no) echo no ;; *) echo "no se pudo comprobar" ;; esac)"

    if [[ ${#F_SEV[@]} -gt 0 ]]; then
        printf '\n%s== Plan recomendado (en este orden) ==%s\n' "$b" "$x"
        local -A seenfix=()
        while IFS= read -r i; do
            [[ "${F_SEV[$i]}" == info || -n "${seenfix[${F_FIX[$i]}]+x}" ]] && continue
            seenfix[${F_FIX[$i]}]=1
            n=$((n + 1)); printf '  %d. %s\n' "$n" "${F_FIX[$i]}"
        done < <(sorted_findings)
        (( n == 0 )) && printf '  Nada urgente: solo mejoras opcionales.\n'
        render_target_records "$c"
        printf '\n  %sDónde se cambia: en el panel DNS de tu dominio%s.\n' "$g" "${DNS_PANEL:+ ($DNS_PANEL)}"
        printf '  Si tu panel pide "Nombre" o "Host", escribe solo _dmarc (o @ para el dominio): muchos paneles\n  añaden el dominio solos y quedaría _dmarc.%s.%s.\n' "$D" "$D"
        printf '  Los cambios tardan de minutos a horas. Vuelve a ejecutar la revisión para comprobarlos.%s\n' "$x"
    fi
    echo
}

# Cómo deberían quedar los registros, completos y listos para copiar
target_spf() {
    local t out=""
    case "$SPF_STATE" in
        none|nx) spf_suggest; return ;;
        ok) ;;
        *) return ;;
    esac
    [[ ${#SPF_WIDE[@]} -gt 0 || ${#SPF_ERRS[@]} -gt 0 || $SPF_LOOKUPS -gt 10 ]] && return    # hay que revisarlo a mano
    [[ "$SPF_ALL" == "-" || "$SPF_ALL" == "~" ]] && [[ $SPF_PTR -eq 0 ]] && return             # ya está bien
    read -r -a _t <<< "$SPF_REC"
    for t in "${_t[@]}"; do
        case "${t,,}" in v=spf1|ptr|ptr:*|+ptr*|[-+~?]all|all) continue ;; esac
        out+=" $t"
    done
    printf 'v=spf1%s -all' "$out"
}
target_dmarc() {
    local rua=${DM[rua]:-mailto:dmarc@$D}
    [[ "$DM_STATE" == dnserr ]] && return
    [[ "$PROVIDER_ID" == none ]] && { printf 'v=DMARC1; p=reject;'; return; }
    if [[ "$DM_EFF" == reject ]] && ! printf '%s\n' "${F_ID[@]}" | grep -q '^DMARC-'; then return; fi
    printf 'v=DMARC1; p=reject; rua=%s' "$rua"
}
render_target_records() {
    local c=$1 b="" x="" sp dm
    [[ $c -eq 1 ]] && { b=$C_BLD; x=$C_RST; }
    sp=$(target_spf); dm=$(target_dmarc)
    [[ -z "$sp" && -z "$dm" ]] && return
    printf '\n%s== Así deberían quedar tus registros ==%s\n' "$b" "$x"
    [[ -n "$sp" ]] && printf '  TXT  %-22s %s\n' "$D" "$sp"
    if [[ -n "$dm" ]]; then
        printf '  TXT  %-22s %s\n' "_dmarc.$D" "$dm"
        if [[ "$PROVIDER_ID" != none && "$DM_EFF" != reject ]]; then
            printf '       Si no estás seguro de qué servicios envían correo por ti (facturación electrónica,\n'
            printf '       Mailchimp, el formulario de tu web...), empieza con p=none, revisa los informes 2-4\n'
            printf '       semanas y luego sube. Mientras estés en p=none la nota se quedará en C: es normal.\n'
        fi
    fi
    [[ "$PROVIDER_ID" == none ]] && printf '  MX   %-22s 0 .\n' "$D"
    [[ -n "$sp" && "$sp" == *-all ]] && printf '  Ojo: con -all, todo lo que envíe correo con tu dominio y no esté en el SPF será rechazado.\n'
}

render_domain_json() {
    local i first r sel bits t
    printf '{\n  "tool": "correo-escudo",\n  "version": "%s",\n  "schema_version": 2,\n  "type": "domain",\n' "$VERSION"
    printf '  "domain": "%s",\n  "generated": "%s",\n' "$(json_esc "$D")" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "provider": "%s",\n  "score": %d,\n  "grade": "%s",\n' "$(json_esc "$PROVIDER")" "$SCORE" "$GRADE"
    printf '  "nameservers": ['; first=1
    for r in "${NS_LIST[@]}"; do [[ $first -eq 1 ]] && first=0 || printf ', '; printf '"%s"' "$(json_esc "$r")"; done
    printf '],\n' 
    printf '  "summary": "%s",\n' "$(json_esc "$(verdict_line)")"
    printf '  "incomplete": ['; first=1
    for r in "${INCOMPLETE[@]}"; do [[ $first -eq 1 ]] && first=0 || printf ', '; printf '"%s"' "$(json_esc "$r")"; done
    printf '],\n  "mx": ['; first=1
    for r in "${MX_LIST[@]}"; do [[ $first -eq 1 ]] && first=0 || printf ', '; printf '"%s"' "$(json_esc "$r")"; done
    printf '],\n  "spf": {"state": "%s", "record": "%s", "all": "%s", "dns_lookups": %d, "void_lookups": %d},\n' \
        "$(json_esc "$SPF_STATE")" "$(json_esc "$SPF_REC")" "$(json_esc "$SPF_ALL")" "$SPF_LOOKUPS" "$SPF_VOID"
    printf '  "dmarc": {"state": "%s", "record": "%s", "policy": "%s", "subdomain_policy": "%s", "reports": %s, "inherited_from": "%s"},\n' \
        "$(json_esc "$DM_STATE")" "$(json_esc "$DM_REC")" "$(json_esc "$DM_EFF")" "$(json_esc "${DM[sp]:-}")" \
        "$([[ -n "${DM[rua]:-}" ]] && echo true || echo false)" "$(json_esc "$DM_FROM")"
    printf '  "dkim": ['; first=1
    for r in "${DK_FOUND[@]}"; do
        IFS='|' read -r sel bits t <<< "$r"
        [[ $first -eq 1 ]] && first=0 || printf ', '
        printf '{"selector": "%s", "key": "%s"}' "$(json_esc "$sel")" "$(json_esc "${bits#\~}")"
    done
    printf '],\n  "mta_sts": "%s",\n  "tls_rpt": %s,\n  "dnssec": "%s",\n' "$(json_esc "${STS_MODE:-$STS_STATE}")" \
        "$([[ "$TLSRPT" == yes ]] && echo true || echo false)" "$(json_esc "$DNSSEC")"
    printf '  "target_records": {"spf": "%s", "dmarc": "%s"},\n' "$(json_esc "$(target_spf)")" "$(json_esc "$(target_dmarc)")"
    printf '  "ok": ['; first=1
    for r in "${OKS[@]}"; do [[ $first -eq 1 ]] && first=0 || printf ', '; printf '\n    "%s"' "$(json_esc "$r")"; done
    printf '\n  ],\n  "findings": ['; first=1
    while IFS= read -r i; do
        [[ -z "$i" ]] && continue
        [[ $first -eq 1 ]] && first=0 || printf ','
        printf '\n    {"severity": "%s", "id": "%s", "title": "%s", "fix": "%s"}' \
            "${F_SEV[$i]}" "${F_ID[$i]}" "$(json_esc "${F_TXT[$i]}")" "$(json_esc "${F_FIX[$i]}")"
    done < <(sorted_findings)
    printf '\n  ]\n}\n'
}

# =============================================================================
#  Muchos dominios a la vez (por ejemplo, los clientes de una consultora)
# =============================================================================
run_list() {
    local file=$1 line n=0 res r c_dom c_grade c_spf c_dmarc c_dkim c_main c_worst c_st first results=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%%#*}; line=${line//[[:space:]]/}
        [[ -z "$line" ]] && continue
        n=$((n + 1)); (( n > 500 )) && die "la lista tiene más de 500 dominios"
        line=$(norm_domain "$line")
        if ! valid_domain "$line"; then results+=("$(clean "$line")|-|-|-|-|dominio no válido|0|err"); continue; fi
        # Cada dominio en un subproceso: un dominio con error no detiene la lista
        res=$( (
            exec 3>&1
            run_domain "$line" 2>&3 >/dev/null
            dm=$DM_EFF; [[ "$DM_STATE" == none ]] && dm=no; [[ "$DM_STATE" == dnserr ]] && dm="?"
            ok_dk=no; [[ ${#DK_FOUND[@]} -gt 0 ]] && ok_dk=si; [[ "$PROVIDER_ID" == none ]] && ok_dk="-"
            sp=no; [[ -n "$SPF_REC" ]] && sp="si${SPF_ALL:+ (${SPF_ALL}all)}"; [[ "$SPF_STATE" == dnserr ]] && sp="?"
            main="sin problemas graves"
            i=$(sorted_findings | head -n1)
            [[ -n "$i" && "${F_SEV[$i]}" != info ]] && main="${F_ID[$i]}"
            st=ok; [[ ${#INCOMPLETE[@]} -gt 0 ]] && { main="$main (incompleto)"; st=inc; }
            printf '\n%s|%s (%s)|%s|%s|%s|%s|%s|%s' "$D" "$GRADE" "$SCORE" "$sp" "$dm" "$ok_dk" "$main" "$WORST" "$st"
        ) )
        if [[ "$res" == *"|"* ]]; then
            results+=("${res##*$'\n'}")
        else
            res=${res#Error: }
            results+=("$line|error|-|-|-|$(clean "${res:-no se pudo consultar}")|0|err")
        fi
    done < "$file"
    (( n == 0 )) && die "la lista $file no tiene dominios"

    LIST_WORST=0; LIST_ERR=0
    for r in "${results[@]}"; do
        IFS='|' read -r _ _ _ _ _ _ c_worst c_st <<< "$r"
        [[ "$c_worst" =~ ^[0-4]$ ]] || c_worst=0
        (( c_worst > LIST_WORST )) && LIST_WORST=$c_worst
        [[ "$c_st" != ok ]] && LIST_ERR=1
    done
    if [[ "$FORMAT" == json ]]; then
        printf '{\n  "tool": "correo-escudo",\n  "version": "%s",\n  "type": "list",\n  "generated": "%s",\n  "domains": [' "$VERSION" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        first=1
        for r in "${results[@]}"; do
            IFS='|' read -r c_dom c_grade c_spf c_dmarc c_dkim c_main c_worst c_st <<< "$r"
            [[ $first -eq 1 ]] && first=0 || printf ','
            printf '\n    {"domain": "%s", "grade": "%s", "spf": "%s", "dmarc": "%s", "dkim": "%s", "main_issue": "%s", "status": "%s"}' \
                "$(json_esc "$c_dom")" "$(json_esc "$c_grade")" "$(json_esc "$c_spf")" "$(json_esc "$c_dmarc")" "$(json_esc "$c_dkim")" "$(json_esc "$c_main")" "$c_st"
        done
        printf '\n  ]\n}\n'
        return 0
    fi
    printf 'correo-escudo v%s — revisión de %d dominios\n\n' "$VERSION" "$n"
    printf '%-32s %-10s %-12s %-12s %-6s %s\n' "Dominio" "Nota" "SPF" "DMARC" "DKIM" "Problema principal"
    for r in "${results[@]}"; do
        IFS='|' read -r c_dom c_grade c_spf c_dmarc c_dkim c_main _ _ <<< "$r"
        printf '%-32s %-10s %-12s %-12s %-6s %s\n' "$c_dom" "$c_grade" "$c_spf" "$c_dmarc" "$c_dkim" "$c_main"
    done
    printf '\nDetalle de cada uno: %s dominio NOMBRE\n' "$0"
}
LIST_WORST=0; LIST_ERR=0

# =============================================================================
#  Análisis de un correo sospechoso (.eml)
#  Un solo programa awk lee el correo en crudo: cabeceras, partes MIME,
#  decodifica base64 y quoted-printable, y busca señales de phishing.
#  Nada del correo se ejecuta ni se abre: los enlaces solo se leen como texto.
#  Salida (TSV): H clave valor · F severidad id texto mitre · U url texto · T adjunto tipo bytes
# =============================================================================
read -r -d '' EML_AWK <<'AWK' || true  # read -d '' devuelve 1 al llegar al final: es normal
# Sin caracteres de control. Los caracteres invisibles que cambian la dirección
# del texto (RTLO y similares) se muestran como <RTLO>: en la terminal harían
# que "Factura_<RTLO>fdp.exe" se viera como "Factura_exe.pdf".
function clean(s) {
    gsub(/[\001-\037\177]/, " ", s)
    if (s ~ /[\200-\377]/) {
        s = utf8fix(s)
        gsub(/\302[\200-\237]/, " ", s)                                   # controles C1 (CSI, OSC...)
        gsub(/\342\200[\252-\256]|\342\201[\246-\251]|\342\200\217|\342\200\216|\330\234/, "<RTLO>", s)
    }
    gsub(/  +/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s
}
# Bytes que no forman UTF-8 válido se cambian por "?" (el JSON debe ser UTF-8 válido)
function utf8fix(s,    out, i, n, b, k, need, ok, j) {
    out = ""; n = length(s)
    for (i = 1; i <= n; i++) {
        b = substr(s, i, 1)
        if (!(b in ORD)) { out = out b; continue }
        k = ORD[b]
        need = (k >= 194 && k <= 223) ? 1 : (k >= 224 && k <= 239) ? 2 : (k >= 240 && k <= 244) ? 3 : -1
        ok = (need > 0 && i + need <= n)
        for (j = 1; ok && j <= need; j++) { b = substr(s, i + j, 1); if (!(b in ORD) || ORD[b] > 191) ok = 0 }
        if (ok) { out = out substr(s, i, need + 1); i += need } else out = out "?"
    }
    return out
}
# Latin-1 / Windows-1252 → UTF-8 (muchos correos en español aún llegan así)
function lat2utf(s,    k, tok) {
    if (s !~ /[\200-\377]/) return s
    # En dos pasos con marcas ASCII (rápido en mawk; byte a byte tardaba segundos)
    for (k = 128; k < 256; k++) if (index(s, CHR[k])) gsub(CHR[k], "\001" k "\002", s)
    for (k = 128; k < 256; k++) {
        tok = "\001" k "\002"
        if (index(s, tok)) gsub(tok, (k >= 160) ? sprintf("%c%c", 192 + int(k / 64), 128 + k % 64) : ((k in CP1252) ? CP1252[k] : "?"), s)
    }
    return s
}
function is_latin(cs) { cs = tolower(cs); return cs ~ /^(iso-?8859-1|iso-?8859-15|latin-?1|windows-1252|cp1252|us-ascii)$/ && cs != "us-ascii" }
# Texto para buscar palabras: minúsculas, sin tildes y con las letras cirílicas
# que imitan a las latinas (а, е, о, р, с...) convertidas
function norm(s) {
    s = tolower(s)
    if (s !~ /[\200-\377]/) return s
    gsub(/\342\200[\213-\215]|\357\273\277|\302\255/, "", s)        # caracteres invisibles (ZWSP, BOM, guion suave)
    gsub(/\303[\241\201]/, "a", s); gsub(/\303[\251\211]/, "e", s); gsub(/\303[\255\215]/, "i", s)
    gsub(/\303[\263\223]/, "o", s); gsub(/\303[\272\232\274\234]/, "u", s); gsub(/\303[\261\221]/, "n", s)
    gsub(/\320[\260\220]/, "a", s); gsub(/\320[\265\225]/, "e", s); gsub(/\320[\276\236]/, "o", s)
    gsub(/\321\200|\320\240/, "p", s); gsub(/\321\201|\320\241/, "c", s); gsub(/\321\203|\320\243/, "y", s)
    gsub(/\321\205|\320\245/, "x", s); gsub(/\321\226|\320\206/, "i", s); gsub(/\320\222/, "b", s)
    gsub(/\320\235/, "h", s); gsub(/\320\234/, "m", s); gsub(/\320\242/, "t", s); gsub(/\320\232/, "k", s)
    return s
}
# Recorta sin partir una letra de varios bytes (é, ñ) por la mitad
function trunc(s, n,    c) {
    if (length(s) <= n) return s
    while (n > 1 && (c = substr(s, n + 1, 1)) in ORD && ORD[c] >= 128 && ORD[c] <= 191) n--
    return substr(s, 1, n) "..."
}
# Dominios y enlaces "desactivados" (evil[.]com, hxxp://) para que nadie los abra por error
function dfd(d) { gsub(/\./, "[.]", d); return d }
function dfa(a,    p) { p = index(a, "@"); return p ? substr(a, 1, p) dfd(substr(a, p + 1)) : dfd(a) }
function dfu(u) { sub(/^[Hh][Tt][Tt][Pp]/, "hxxp", u); gsub(/\./, "[.]", u); return u }
function nz(s) { return s == "" ? "-" : s }

# --- Decodificadores ---------------------------------------------------------------
function b64init(    i, c) {
    c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for (i = 1; i <= 64; i++) B64[substr(c, i, 1)] = i - 1
    b64ready = 1
}
function b64dec(s,    out, i, n, v, q) {
    if (!b64ready) b64init()
    gsub(/[^A-Za-z0-9+\/]/, "", s)
    out = ""; n = length(s); q = 0; v = 0
    for (i = 1; i <= n; i++) {
        v = v * 64 + B64[substr(s, i, 1)]
        if (++q == 4) { out = out sprintf("%c%c%c", int(v / 65536), int(v / 256) % 256, v % 256); q = 0; v = 0 }
    }
    if (q == 2) out = out sprintf("%c", int(v / 16))
    else if (q == 3) out = out sprintf("%c%c", int(v / 1024), int(v / 4) % 256)
    return out
}
function hexval(h,    i, c, v) {
    v = 0; h = toupper(h)
    for (i = 1; i <= length(h); i++) { c = index("0123456789ABCDEF", substr(h, i, 1)); if (!c) return -1; v = v * 16 + c - 1 }
    return v
}
# Quoted-printable (y la variante "Q" de las cabeceras si q = 1)
function qpdec(s, q,    out, i, n, c, v) {
    out = ""; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "=" && i + 2 <= n && (v = hexval(substr(s, i + 1, 2))) >= 0) { out = out sprintf("%c", v); i += 2 }
        else if (q && c == "_") out = out " "
        else out = out c
    }
    return out
}
function pctdec(s,    out, i, n, c, v) {
    out = ""; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "%" && i + 2 <= n && (v = hexval(substr(s, i + 1, 2))) >= 0) { out = out sprintf("%c", v); i += 2 }
        else out = out c
    }
    return out
}
# Palabras codificadas de las cabeceras (RFC 2047): =?utf-8?B?...?= y =?utf-8?Q?...?=
function hdrdec(s,    out, pre, m, p, txt, prev) {
    out = ""; prev = 0
    while (match(s, /=\?[^? ]+\?[BbQq]\?[^? ]*\?=/)) {
        pre = substr(s, 1, RSTART - 1); m = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
        if (prev && pre ~ /^[ \t]*$/) pre = ""
        split(m, p, "?")
        txt = (toupper(p[3]) == "B") ? b64dec(p[4]) : qpdec(p[4], 1)
        if (is_latin(p[2])) txt = lat2utf(txt)
        out = out pre txt; prev = 1
    }
    return out s
}
# Parámetro de una cabecera (boundary, filename, name), respetando mayúsculas del valor
function param(v, name,    lv, pos, rest, val, q) {
    lv = tolower(v)
    if (!match(lv, "(^|[; \t\r\n/])" name "[ \t\r\n]*=[ \t\r\n]*")) return ""
    rest = substr(v, RSTART + RLENGTH)
    if (substr(rest, 1, 1) == "\"" || substr(rest, 1, 1) == "'") { q = substr(rest, 1, 1); rest = substr(rest, 2); pos = index(rest, q); val = pos ? substr(rest, 1, pos - 1) : rest }
    else { val = rest; sub(/[; \t\r\n>].*$/, "", val) }
    return val
}
# Nombre de un adjunto: filename= o name=, en RFC 2047 o RFC 2231 (incluido
# el nombre partido en trozos: filename*0=..., filename*1=...)
function rfc2231(v, base,    f, k, piece, out, cs) {
    f = param(v, base "\\*")
    if (f != "") { cs = f; sub(/'.*$/, "", cs); sub(/^[^']*'[^']*'/, "", f); f = pctdec(f); return is_latin(cs) ? lat2utf(f) : f }
    out = ""
    for (k = 0; k < 30; k++) {
        piece = param(v, base "\\*" k "\\*")
        if (piece != "") { if (k == 0) { cs = piece; sub(/'.*$/, "", cs); sub(/^[^']*'[^']*'/, "", piece) } out = out pctdec(piece); continue }
        piece = param(v, base "\\*" k)
        if (piece == "") break
        out = out piece
    }
    return (out != "" && is_latin(cs)) ? lat2utf(out) : out
}
function filename_of(cd, ct,    f) {
    f = rfc2231(cd, "filename"); if (f != "") return f
    f = rfc2231(ct, "name"); if (f != "") return f
    f = param(cd, "filename"); if (f == "") f = param(ct, "name")
    return hdrdec(f)
}

# --- Dominios -----------------------------------------------------------------------
function addr_of(v,    a) {
    if (!index(v, "@")) return ""
    if (match(v, /<[^<>]*>[ \t]*$/)) { a = substr(v, RSTART + 1, RLENGTH - 2); sub(/>[ \t]*$/, "", a) }
    else if (match(v, /[^ \t<>"(),;:]+@[^ \t<>"(),;:]+/)) a = substr(v, RSTART, RLENGTH)
    else a = ""
    return tolower(clean(a))
}
function name_of(v,    n) {
    n = v
    if (match(n, /<[^<>]*>[ \t]*$/)) n = substr(n, 1, RSTART - 1)
    else n = ""
    gsub(/"/, "", n)
    return clean(hdrdec(n))
}
function dom_of(a) { return (index(a, "@")) ? substr(a, index(a, "@") + 1) : "" }
# Dominio "registrable" aproximado: google.com, empresa.com.pa
function reg(h,    n, p) {
    n = split(h, p, ".")
    if (n <= 2) return h
    if (length(p[n]) == 2 && p[n - 1] ~ /^(com|net|org|gob|gov|edu|ac|co|or|ne|go|mil|nom|sld|ing|abo|med)$/) return p[n - 2] "." p[n - 1] "." p[n]
    return p[n - 1] "." p[n]
}
function label_of(h,    r) { r = reg(h); sub(/\..*$/, "", r); return r }
function same_or_sub(h, d) { return (h == d || (length(h) > length(d) && substr(h, length(h) - length(d)) == "." d)) }
function lev(a, b,    i, j, la, lb, d, c, x, y, z) {
    la = length(a); lb = length(b)
    if (la - lb > 3 || lb - la > 3) return 9
    for (i = 0; i <= la; i++) d[i, 0] = i
    for (j = 0; j <= lb; j++) d[0, j] = j
    for (i = 1; i <= la; i++) for (j = 1; j <= lb; j++) {
        c = (substr(a, i, 1) == substr(b, j, 1)) ? 0 : 1
        x = d[i - 1, j] + 1; y = d[i, j - 1] + 1; z = d[i - 1, j - 1] + c
        d[i, j] = (x < y ? (x < z ? x : z) : (y < z ? y : z))
    }
    return d[la, lb]
}
# Letras que se confunden a simple vista: rn→m, vv→w, 0→o, 1→l, l→i...
function skel(s) { gsub(/rn/, "m", s); gsub(/vv/, "w", s); gsub(/0/, "o", s); gsub(/[1l|]/, "i", s); gsub(/3/, "e", s); gsub(/5/, "s", s); gsub(/-/, "", s); return s }
# ¿h imita a mi dominio m (sin serlo)?
function lookalike(h, m,    lh, lm) {
    if (h == "" || reg(h) == reg(m)) return 0
    lh = label_of(h); lm = label_of(m)
    if (length(lm) < 4) return 0
    if (lh == lm) return 1                                   # mismo nombre, otra terminación: empresa.com vs empresa.com.pa
    if (skel(lh) == skel(lm)) return 1                       # ernpresa / empresa, ernpresa / empresa
    if (lev(lh, lm) <= (length(lm) >= 8 ? 2 : 1)) return 1   # una o dos letras cambiadas
    if (length(lm) >= 5 && index(lh, lm)) return 1           # empresa-pagos, soporte-empresa
    return 0
}
# "empresa-demo-com-pa.login-portal.xyz": el nombre de tu empresa como subdominio
# de otro sitio. Se excluyen servicios conocidos que usan tu nombre de forma legítima.
function embeds(h, m,    lm, r) {
    if (h == "" || same_or_sub(h, reg(m))) return 0
    lm = label_of(m); r = reg(h)
    if (length(lm) < 5 || lookalike(h, m)) return 0
    if (r ~ /^(sharepoint\.com|onmicrosoft\.com|zendesk\.com|atlassian\.net|salesforce\.com|force\.com|slack\.com|myshopify\.com|wordpress\.com|github\.io|office\.com)$/) return 0
    return index(h, lm) > 0
}
function hasword(t, w,    p, b, a, rest, off) {
    off = 0; rest = t
    while ((p = index(rest, w)) > 0) {
        b = (off + p > 1) ? substr(t, off + p - 1, 1) : " "
        a = substr(t, off + p + length(w), 1)
        if (b !~ /[a-z0-9]/ && a !~ /[a-z0-9]/) return 1
        off += p; rest = substr(t, off + 1)
    }
    return 0
}

# Quita comentarios (...) y textos entre comillas en UNA sola pasada de
# izquierda a derecha (como manda RFC 5322). Hacerlo en dos pasos permitía
# que un remitente como "); dmarc=pass ("@evil.com escapara de las comillas.
function strip_cfws(s,    out, i, n, c, q, d) {
    out = ""; n = length(s); q = 0; d = 0
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\\" && (q || d)) { i++; continue }
        if (q) { if (c == "\"") q = 0; continue }
        # Dentro de un comentario, una dirección entre comillas también se salta:
        # algunos servidores copian ahí la dirección del remitente tal cual
        if (d) { if (c == "\"") q = 1; else if (c == "(") d++; else if (c == ")") d--; continue }
        if (c == "\"") { q = 1; out = out " "; continue }
        if (c == "(") { d = 1; out = out " "; continue }
        out = out c
    }
    return out
}

# --- Hallazgos ----------------------------------------------------------------------
function flag(sev, id, text, mitre) {
    if (id in fseen) { fcnt[id]++; return }
    fseen[id] = 1; fcnt[id] = 1; nf++
    fsev[nf] = sev; fid[nf] = id; ftxt[nf] = text; fmit[nf] = mitre
}
function addbrand(name, kws, doms, toks) { nb++; bname[nb] = name; bkw[nb] = kws; bdom[nb] = doms; btok[nb] = toks }
# ¿El dominio h lleva el nombre de una marca (bgeneral-seguridad.com) sin ser suyo?
# Dominios de la marca con otra terminación (bgeneral.com.pa, fedex.com.pa,
# netflix.net): el nombre principal coincide exactamente con el de la marca
# (Solo dominios verificados: un nombre igual en otra terminación lo puede
# registrar cualquiera, p. ej. bgeneral.net)
function brand_own(h, i) { return brand_ok(h, i) }
function brand_of_label(h,    i) { for (i = 1; i <= nb; i++) if (brand_own(h, i)) return i; return 0 }
function brand_lookalike(h,    i, n, t, k, sh) {
    if (h == "" || h ~ /\.onmicrosoft\.com$/) return 0       # cuentas de Microsoft 365: ver MS-TENANT
    sh = skel(h)
    for (i = 1; i <= nb; i++) {
        if (btok[i] == "" || brand_own(h, i)) continue
        n = split(btok[i], t, ",")
        for (k = 1; k <= n; k++) if (t[k] != "" && index(sh, skel(t[k]))) return i
    }
    return 0
}
function brand_ok(h, i,    n, d, k) {
    n = split(bdom[i], d, ",")
    for (k = 1; k <= n; k++) {
        if (substr(d[k], 1, 1) == ".") { if (length(h) > length(d[k]) && substr(h, length(h) - length(d[k]) + 1) == d[k]) return 1 }
        else if (same_or_sub(h, d[k])) return 1
    }
    return 0
}

# --- Enlaces y adjuntos -------------------------------------------------------------
# Entidades HTML (&#104; &ntilde; &colon;...). Se recorre partiendo por "&"
# una sola vez, para que un correo con miles de entidades no sea lento.
function entdec(s,    n, P, i, m, v, nm, rep, O, no) {
    if (!index(s, "&")) return s
    n = split(s, P, "&"); no = 1; O[1] = P[1]
    for (i = 2; i <= n; i++) {
        if (match(P[i], /^(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z]+);?/)) {
            m = substr(P[i], 1, RLENGTH); nm = m; sub(/;$/, "", nm)
            if (nm ~ /^#[xX]/) v = hexval(substr(nm, 3)); else if (nm ~ /^#/) v = substr(nm, 2) + 0; else v = -1
            if (v >= 0) rep = (v > 0 && v < 128) ? sprintf("%c", v) : (v >= 160 && v < 256) ? sprintf("%c%c", 192 + int(v / 64), 128 + v % 64) : (v >= 8203 && v <= 8205) ? "\342\200\213" : "?"
            else if (nm in ENT) rep = ENT[nm]
            else { O[++no] = "&" P[i]; continue }
            O[++no] = rep substr(P[i], RLENGTH + 1)
        } else O[++no] = "&" P[i]
    }
    return joinarr(O, no)
}
# Une un arreglo por parejas (unir de uno en uno es muy lento en awk)
function joinarr(A, n,    i, j) {
    if (n < 1) return ""
    while (n > 1) { j = 0; for (i = 1; i <= n; i += 2) A[++j] = (i < n) ? A[i] A[i + 1] : A[i]; n = j }
    return A[1]
}
# Servicios que reescriben los enlaces (Safe Links de Microsoft, Mailchimp,
# SendGrid...): el texto y el enlace no coinciden y es normal. Si el destino
# real viene dentro del enlace (url=, q=...), se usa ese.
# 1 = protección del correo (Safe Links, Proofpoint, Mimecast, Google): el destino
#     real viene dentro del enlace y se puede leer.
# 2 = seguimiento de boletines (Mailchimp, SendGrid...): el destino real no se ve.
function redirector(h, u) {
    if (h ~ /(^|\.)(safelinks\.protection\.outlook\.com|urldefense\.com|urldefense\.proofpoint\.com|mimecast\.com|cudasvc\.com)$/) return 1
    if (h ~ /^(www\.)?google\.[a-z.]+$/ && tolower(u) ~ /^https?:\/\/[^\/]+\/url\?/) return 1
    if (h ~ /(^|\.)(list-manage\.com|sendgrid\.net|mandrillapp\.com|hubspotlinks\.com|rs6\.net|awstrack\.me|mailgun\.org|sparkpostmail\.com|mlsend\.com|exacttarget\.com|sendibt3\.com)$/) return 2
    return 0
}
function real_target(u,    low, t) {
    low = tolower(u)
    if (match(low, /[?&](url|u|q|target|redirect|r)=https?(%3a|:)/)) {
        t = substr(u, RSTART, length(u)); sub(/^[?&][a-zA-Z]+=/, "", t); sub(/&.*$/, "", t)
        t = tolower(pctdec(t)); sub(/^[a-z]+:\/\//, "", t); sub(/[\/?#\\:].*$/, "", t); sub(/^.*@/, "", t)
        return t
    }
    return ""
}
function from_dom() { return dom_of(addr_of(H["from"])) }
function check_link(url, text,    u, low, host, th, tt, dest, bl, rk) {
    u = entdec(clean(url)); gsub(/[ \t\r\n]/, "", u); low = tolower(u)
    if (low ~ /^(javascript|vbscript|data):/) {
        nlinks++
        flag("high", "LINK-SCRIPT", "Enlace que ejecuta código o esconde contenido (" substr(low, 1, index(low, ":")) ")", "T1566.002")
        print "U\t" trunc(u, 200) "\t" nz(trunc(clean(text), 80)) "\t-"; return
    }
    if (low !~ /^(https?|ftp):\/\//) return
    # Se revisan hasta 5000 enlaces (antes, poner 300 enlaces inocentes primero
    # escondía el enlace malo del final); se listan los 300 primeros distintos
    if (++nlinks > 5000) { linkcap = 1; return }
    host = low; sub(/^[a-z]+:\/\//, "", host); sub(/[\/?#\\].*$/, "", host)
    if (index(host, "@")) {
        flag("high", "LINK-USERINFO", "Enlace con truco de @: lo de antes de la @ es decoración, el sitio real es lo que va después (" dfd(trunc(clean(host), 60)) ")", "T1566.002")
        sub(/^.*@/, "", host)
    }
    sub(/:[0-9]*$/, "", host)
    tt = trunc(clean(text), 80)
    if (tt ~ /:\/\// || tolower(tt) ~ /^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/|$)/) tt = dfu(tt)   # que tampoco se pueda pulsar
    if (!(u in useen)) { useen[u] = 1; if (++nprint <= 300) print "U\t" trunc(u, 2000) "\t" nz(tt) "\t" nz(host) }
    if (!(host in hostseen)) { hostseen[host] = 1; nhosts++; hostlist[nhosts] = host }
    if (host ~ /[\200-\377]/ && (bl = brand_of_label(norm(host))))
        flag("critical", "BRAND-HOMOGLYPH", "Enlace a " dfd(clean(host)) ": se escribe con letras de otro alfabeto para parecer " bname[bl], "T1566.002")
    else if (host ~ /[\200-\377]/)
        flag("medium", "HOST-UNICODE", "Enlace a un dominio con letras no latinas que imitan a las normales (" dfd(clean(host)) ")", "T1566.002")
    # Consentimiento OAuth: la página de inicio de sesión es la real de Microsoft o
    # Google, pero el permiso se lo das a una aplicación del atacante
    if (host ~ /^(login\.microsoftonline\.com|login\.live\.com|accounts\.google\.com)$/ && low ~ /(oauth2|authorize)/ && match(low, /redirect_uri=[^&]+/)) {
        th = pctdec(substr(low, RSTART + 13, RLENGTH - 13)); sub(/^[a-z]+:\/\//, "", th); sub(/[\/?#:].*$/, "", th)
        if (th != "" && reg(th) !~ /^(microsoft|microsoftonline|office|live|google|googleusercontent|sharepoint)\.com$/)
            flag("high", "OAUTH-CONSENT", "Enlace que pide permisos para una aplicación externa (" dfd(th) ") usando la página real de " (host ~ /google/ ? "Google" : "Microsoft") ": si aceptas, el atacante entra a tu correo sin tu contraseña", "T1528")
    }
    if (host ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || host ~ /^\[/)
        flag("high", "LINK-IP", "Enlace a una dirección IP en lugar de a un sitio con nombre (" dfd(host) "): las empresas legítimas no hacen eso", "T1566.002")
    if (host ~ /(^|\.)xn--/)
        flag("medium", "LINK-PUNY", "Enlace con un dominio internacional (" dfd(host) "): puede imitar letras de otro sitio", "T1566.002")
    if (reg(host) in SHORT)
        flag("medium", "LINK-SHORT", "Enlace acortado (" dfd(host) "): esconde el sitio real", "T1566.002")
    if ((bl = brand_lookalike(norm(host))))
        flag("high", "BRAND-LOOKALIKE-LINK", "Un enlace lleva a " dfd(host) ", que usa el nombre de " bname[bl] " pero no es suyo", "T1566.002")
    # El texto visible parece una dirección, pero el enlace lleva a otra
    dest = host; rk = redirector(host, u)
    if (rk == 1) dest = real_target(u)
    tt = tolower(clean(text)); sub(/^[ \t]+/, "", tt); sub(/[ \t]+$/, "", tt)
    if (tt ~ /^(https?:\/\/)?(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/[^ ]*)?$/ && tt ~ /\.[a-z][a-z]+(\/|$)/) {
        th = tt; sub(/^https?:\/\//, "", th); sub(/[\/?#].*$/, "", th)
        # Un nombre de archivo (Cotizacion.xlsx) no es una dirección web; y el mismo
        # nombre con otra terminación de la propia marca (bgeneral.com → .com.pa) es normal
        if (tt ~ /\.(xlsx?|docx?|pptx?|pdf|csv|txt|zip|png|jpe?g|gif|mp4|mp3)$/ || (label_of(th) == label_of(dest) && brand_lookalike(dest) == 0 && brand_of_label(dest))) {
            rk = -1
        } else if (rk == 2) {
            # Enlace de seguimiento: normal en boletines, salvo que el texto
            # muestre un sitio que no es del remitente (p. ej. el de un banco)
            if (reg(th) != reg(from_dom()) && reg(th) !~ /^(facebook|instagram|twitter|x|linkedin|youtube|tiktok|whatsapp)\.com$/)
                flag("low", "LINK-HIDDEN", "El enlace dice \"" dfu(trunc(tt, 50)) "\" pero pasa por un servicio de seguimiento (" dfd(reg(host)) ") que esconde el destino real", "T1566.002")
        } else if (rk != -1 && dest != "" && reg(th) != reg(dest))
            flag("high", "LINK-MISMATCH", "El enlace dice \"" dfu(trunc(tt, 50)) "\" pero lleva a " dfd(dest), "T1566.002")
    }
}

function check_att(name, ct,    n, ext) {
    natt++
    # Windows ignora los puntos y espacios del final: "pago.exe." es pago.exe
    n = tolower(name); sub(/[ .\t]+$/, "", n); ext = n
    if (index(ext, ".")) sub(/^.*\./, "", ext); else ext = ""
    if (index(name, "\342\200\256"))
        flag("critical", "ATT-RTLO", "Adjunto con un carácter invisible (<RTLO>) que da la vuelta al nombre: \"" clean(name) "\" se ve como otra cosa", "T1036.002")
    if (n ~ /\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|rtf|csv|zip|mp3|wav)[ _.]*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|msi|lnk|jar|html?|svg|iso|img)$/)
        flag("critical", "ATT-DOUBLE", "Adjunto con doble extensión: \"" clean(name) "\" parece un documento pero es ." ext, "T1036.007")
    if (ext ~ /^(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|wsh|wsc|hta|ps1|psm1|msi|msp|lnk|jar|cpl|reg|scf|url|inf|appx|msix|appinstaller|xll|iqy|slk|xbap|application|settingcontent-ms)$/)
        flag("critical", "ATT-EXEC", "Adjunto ejecutable o script (." ext "): abrirlo puede instalar un programa malicioso", "T1566.001")
    else if (ext ~ /^(iso|img|vhd|vhdx)$/)
        flag("high", "ATT-DISK", "Adjunto de imagen de disco (." ext "): se usa para saltarse las protecciones de Windows", "T1553.005")
    else if (ext ~ /^(html?|shtml|xhtml|mht|mhtml|svgz?)$/)
        flag("high", "ATT-HTML", "Adjunto ." ext ": suele abrir una página falsa para robar contraseñas o esconder descargas (HTML/SVG smuggling)", "T1027.006")
    else if (ext ~ /^(docm|xlsm|pptm|dotm|xlam|ppam|xlsb|one|onepkg|chm)$/)
        flag("high", "ATT-MACRO", "Adjunto de Office con macros o de OneNote (." ext "): puede ejecutar código al abrirlo", "T1566.001")
    else if (ext ~ /^(zip|rar|7z|gz|tar|ace|cab|arj|xz|bz2)$/)
        flag("low", "ATT-ARCHIVE", "Adjunto comprimido (." ext "): revisa qué contiene antes de abrir nada", "T1566.001")
}

# --- Texto: HTML y texto plano -----------------------------------------------------
function analyze_text(t, html,    tl, n, i, off, ch, tag, gt, href, aend, atext, u, ntag, tx, P, sch, rest, k, cnt, cand) {
    if (html) {
        # Para buscar palabras: sin etiquetas y con las entidades (&ntilde;) traducidas
        tx = t; gsub(/<[^>]*>/, " ", tx); tx = entdec(tx)
        if (tx ~ /<form|[Tt][Yy][Pp][Ee][ \t]*=[ \t]*["']?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]/ || tolower(t) ~ /<form[^>]*action[ \t]*=[ \t]*["']?https?:/ || tolower(t) ~ /type[ \t]*=[ \t]*["']?password/)
            flag("high", "HTML-FORM", "El correo trae un formulario para escribir datos (contraseña) dentro del propio mensaje", "T1566")
    } else tx = t
    if (length(alltext) < 300000) alltext = alltext " " substr(tx, 1, 300000)
    tl = tolower(t)
    if (html) {
        # <area> y <v:roundrect> (botones de Outlook) también llevan enlaces: se
        # convierten en "<a" conservando la longitud para no descuadrar posiciones
        if (tl ~ /<area[ \t\r\n\/]/) { gsub(/<area[ \t\r\n\/]/, "   <a ", tl) }
        cnt = 0
        while (cnt < 200 && match(tl, /<v:[a-z]+[ \t\r\n\/]/)) {
            cnt++; k = RLENGTH
            tl = substr(tl, 1, RSTART - 1) sprintf("%" (k - 3) "s", "") "<a " substr(tl, RSTART + k)
        }
        # Se parte el HTML por "<a" una sola vez (recorrerlo con substr en cada
        # enlace era lento con correos grandes hechos a propósito)
        n = split(tl, ch, /<a[ \t\r\n\/]/)
        off = length(ch[1]) + 1
        for (i = 2; i <= n && ntag < 20000; i++) {
            ntag++
            u = substr(t, off + 3, length(ch[i]))          # el mismo trozo, con mayúsculas originales
            off += 3 + length(ch[i])
            gt = index(u, ">"); if (!gt) continue
            tag = substr(u, 1, gt - 1)
            aend = index(ch[i], "</a")
            if (aend > gt) atext = substr(u, gt + 1, aend - gt - 1)
            else { atext = substr(u, gt + 1); sub(/<.*$/, "", atext) }      # <a> sin cerrar o anidado
            gsub(/<[^>]*>/, " ", atext); atext = entdec(atext)
            href = param(tag, "href")
            if (href != "") check_link(href, atext)
        }
        if (n - 1 > 20000) linkcap = 1
    }
    # Direcciones escritas como texto (también dentro del HTML): se parte por
    # "://" una sola vez; las ya vistas en un href no se repiten
    n = split(tl, P, /:\/\//)
    off = length(P[1]) + 1
    for (i = 2; i <= n && i < 5000; i++) {
        sch = P[i - 1]; if (!match(sch, /(https?|ftp)$/)) { off += 3 + length(P[i]); continue }
        sch = substr(sch, RSTART)
        rest = substr(t, off + 3, length(P[i])); off += 3 + length(P[i])
        if (!match(rest, /^[^ \t\r\n<>"']+/)) continue
        cand = sch "://" substr(rest, 1, RLENGTH); sub(/[.,;:!?)]+$/, "", cand)
        if (!(entdec(cand) in useen)) check_link(cand, "")
    }
}

# Enlaces dentro de un PDF: /URI (http://...)
function pdf_links(b,    c, u) {
    c = 0
    while (c < 50 && match(b, /\/URI[ \t\r\n]*\([^)]*\)/)) {
        u = substr(b, RSTART, RLENGTH); b = substr(b, RSTART + RLENGTH); c++
        sub(/^\/URI[ \t\r\n]*\(/, "", u); sub(/\)$/, "", u)
        check_link(u, "(enlace dentro del PDF)")
    }
}
# Cabecera de un .zip: ¿está protegido con contraseña? ¿qué archivo trae?
function zip_check(d, zname,    flags, nl, inner) {
    if (substr(d, 1, 4) != "PK\003\004") return
    flags = ORDB(substr(d, 7, 1))
    nl = ORDB(substr(d, 27, 1)) + 256 * ORDB(substr(d, 28, 1))
    inner = (nl > 0 && nl < 200) ? substr(d, 31, nl) : ""
    if (flags % 2 == 1)
        flag("high", "ATT-ENCRYPTED", "Adjunto comprimido con contraseña (" clean(zname) "): así los antivirus no pueden revisarlo", "T1027.013")
    if (inner != "") { zipinner = 1; check_att(inner, ""); zipinner = 0 }
}
function ORDB(c) { return (c in ORD) ? ORD[c] : (c == "" ? 0 : ORDA[c]) }

# --- Partes MIME ----------------------------------------------------------------------
function part_begin(ct, cte, cd) {
    pct = tolower(ct); sub(/;.*$/, "", pct); gsub(/[ \t]/, "", pct)
    pcte = tolower(cte); gsub(/[ \t]/, "", pcte)
    pname = filename_of(cd, ct)
    pattach = (pname != "" || tolower(cd) ~ /^[ \t]*attachment/)
    pcs = param(ct, "charset")
    pext = tolower(pname); sub(/[ .\t]+$/, "", pext); sub(/^.*\./, "", pext)
    # Algunos adjuntos se leen por dentro (sin abrirlos): invitaciones .ics,
    # enlaces dentro de PDF y el nombre del archivo dentro de un .zip
    pdecode = (!pattach && (pct == "" || pct ~ /^text\/(plain|html|calendar)$/)) || (pattach && (pext == "ics" || pext == "pdf" || pct == "text/calendar"))
    pzip = (pattach && (pext == "zip" || pct ~ /zip/)); pzfirst = ""
    pbuf = ""; pbytes = 0
}
function part_line(l) {
    pbytes += length(l) + 1
    if (pzip && length(pzfirst) < 200) pzfirst = pzfirst l
    # Para la huella SHA-256: el adjunto se guarda TAL CUAL (en base64, sin
    # decodificar) en una carpeta temporal privada que se borra al terminar
    if (pattach && adir != "" && pcte == "base64" && pbytes < 27000000 && natt < 100) { afile = adir "/" (natt + 1) ".b64"; print l > afile }
    if (!pdecode) return
    if (pbytes > 400000) { ptrunc = 1; return }    # basta con el principio (y se avisa si se cortó)
    if (tdecoded > 3000000) { ptrunc = 1; return }   # tope de texto por correo
    tdecoded += length(l)
    # Se guardan trozos y se unen al final por parejas: sumar texto línea a
    # línea a una cadena cada vez más larga es muy lento en awk
    if (pcte == "base64") pl[++npl] = b64dec(l)
    else if (pcte == "quoted-printable") { if (sub(/=$/, "", l)) pl[++npl] = qpdec(l, 0); else pl[++npl] = qpdec(l, 0) "\n" }
    else pl[++npl] = l "\n"
}
function joinparts(    n, i, j) {
    n = npl
    while (n > 1) {
        j = 0
        for (i = 1; i <= n; i += 2) pl[++j] = (i < n) ? pl[i] pl[i + 1] : pl[i]
        n = j
    }
    pbuf = (npl > 0) ? pl[1] : ""
    delete pl; npl = 0
}
function part_end(    size) {
    if (afile != "") { close(afile); afile = "" }
    joinparts()
    if (!pattach && is_latin(pcs)) pbuf = lat2utf(substr(pbuf, 1, 400000))
    if (pattach) {
        size = (pcte == "base64") ? int(pbytes * 3 / 4) : pbytes
        nm = clean(pname); if (nm == "") nm = "(sin nombre)"
        print "T\t" trunc(nm, 120) "\t" nz(clean(pct)) "\t" size "\t" natt + 1
        check_att(pname, pct)
        if (pct ~ /^image\// || pext ~ /^(png|jpe?g|gif|bmp|webp|pdf)$/) nimg++
        if (pext == "ics" || pct == "text/calendar") analyze_text(pbuf, 0)
        if (pext == "pdf") pdf_links(pbuf)
        if (pzip && pcte == "base64") zip_check(b64dec(pzfirst), nm)
    } else if (pct == "text/html") analyze_text(pbuf, 1)
    else analyze_text(pbuf, 0)
    pbuf = ""
}
function hdr_store(    n, v) {
    if (cur == "") return
    n = cur; v = curv; sub(/^[ \t]+/, "", v)
    # Una cabecera gigante no debe frenar el análisis (la de autenticación puede
    # ser larga de verdad: muchas firmas DKIM antes del resultado DMARC)
    if (length(v) > (n == "authentication-results" ? 65536 : 4096)) v = substr(v, 1, (n == "authentication-results" ? 65536 : 4096))
    if (state == "H") {
        if (n ~ /^(from|to|subject|date|received|message-id|content-type|authentication-results|return-path|mime-version)$/) nknown++
        if (n == "authentication-results") { nauth++; if (nauth == 1) H["auth"] = v }
        else if (n == "received") {
            # IP de origen: la primera dirección pública que aparece en los Received
            # (de arriba abajo, el más reciente primero; se queda con el último visto)
            nrecv++
            if (match(v, /\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]/)) { ipc = substr(v, RSTART + 1, RLENGTH - 2); if (ipc !~ /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) sender_ip = ipc }
        }
        else if (n == "dkim-signature") { ndkim++; if (match(v, /(^|;)[ \t]*d=[^;]+/)) { dd = substr(v, RSTART, RLENGTH); sub(/^.*d=/, "", dd); gsub(/[ \t]/, "", dd); dkimd = tolower(dd) } }
        else if (!(n in H)) H[n] = v
    } else {
        PH[n] = v
    }
    cur = ""
}
function push_bnd(b) {
    if (nbnd >= 50) { toomany = 1; return }         # tope de anidamiento
    if (b == "" || b in BLEVEL) { bnd[++nbnd] = "\001"; return }
    bnd[++nbnd] = b; BLEVEL[b] = nbnd
}
# "Wed, 7 Oct 2026 07:45:00 -0500" → "2026-10-07T07:45:00-05:00"
function isodate(d,    w, n, i, mo, dd, yy, tm, tz, M) {
    d = clean(d); sub(/^[A-Za-z]+,[ ]*/, "", d)
    n = split(d, w, " ")
    if (n < 4) return ""
    split("jan feb mar apr may jun jul aug sep oct nov dec", M, " ")
    mo = 0; for (i = 1; i <= 12; i++) if (tolower(substr(w[2], 1, 3)) == M[i]) mo = i
    dd = w[1] + 0; yy = w[3] + 0; tm = w[4]; tz = (n >= 5) ? w[5] : "+0000"
    if (!mo || !dd || yy < 1970 || tm !~ /^[0-9][0-9]?:[0-9][0-9](:[0-9][0-9])?$/) return ""
    if (length(tm) == 5) tm = tm ":00"; if (length(tm) == 7) tm = "0" tm
    if (tz !~ /^[+-][0-9][0-9][0-9][0-9]$/) tz = "+0000"
    return sprintf("%04d-%02d-%02dT%s%s:%s", yy, mo, dd, tm, substr(tz, 1, 3), substr(tz, 4, 2))
}
function nwords(s,    a) { return split(s, a, /[^a-z0-9]+/) - (s ~ /^[^a-z0-9]/) - (s ~ /[^a-z0-9]$/) }
function tenant_mine(d,    t, k, n, mm) { t = d; sub(/\.onmicrosoft\.com$/, "", t); n = split(mine, mm, ","); for (k = 1; k <= n; k++) if (mm[k] != "" && t == label_of(mm[k])) return 1; return 0 }
function headers_done() {
    if (state == "H") {
        ct = H["content-type"]
        if (tolower(ct) ~ /^[ \t]*multipart\//) {
            push_bnd(param(ct, "boundary")); state = "B"
        } else {
            part_begin(ct, H["content-transfer-encoding"], H["content-disposition"]); state = "PB"
        }
    } else {
        ct = PH["content-type"]
        # Un correo reenviado como adjunto: se analiza también su contenido
        if (tolower(ct) ~ /^[ \t]*message\/rfc822/ && nembed < 10) { nembed++; delete PH; cur = ""; state = "PH"; return }
        if (tolower(ct) ~ /^[ \t]*multipart\//) { push_bnd(param(ct, "boundary")); state = "B" }
        else { part_begin(ct, PH["content-transfer-encoding"], PH["content-disposition"]); state = "PB" }
    }
}

BEGIN {
    state = "H"; nbnd = 0; nf = 0; nb = 0
    for (i = 128; i < 256; i++) { CHR[i] = sprintf("%c", i); ORD[CHR[i]] = i }
    for (i = 1; i < 128; i++) ORDA[sprintf("%c", i)] = i
    split("amp:38 colon:58 sol:47 period:46 lt:60 gt:62 quot:34 apos:39 nbsp:32 tab:32 newline:32", ee, " ")
    for (i in ee) { split(ee[i], e2, ":"); ENT[e2[1]] = sprintf("%c", e2[2]) }
    split("aacute:\303\241 eacute:\303\251 iacute:\303\255 oacute:\303\263 uacute:\303\272 ntilde:\303\261 uuml:\303\274 Aacute:\303\201 Eacute:\303\211 Iacute:\303\215 Oacute:\303\223 Uacute:\303\232 Ntilde:\303\221 iexcl:\302\241 iquest:\302\277 zwj:\342\200\213 zwnj:\342\200\213", ee, " ")
    for (i in ee) { split(ee[i], e2, ":"); ENT[e2[1]] = e2[2] }
    CP1252[128] = "\342\202\254"; CP1252[133] = "\342\200\246"; CP1252[145] = "\342\200\230"; CP1252[146] = "\342\200\231"
    CP1252[147] = "\342\200\234"; CP1252[148] = "\342\200\235"; CP1252[150] = "\342\200\223"; CP1252[151] = "\342\200\224"
    split("bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly cutt.ly rb.gy shorturl.at tiny.cc rebrand.ly s.id t.ly bitly.com qrco.de", sh, " ")
    for (i in sh) SHORT[sh[i]] = 1
    split("gmail.com googlemail.com hotmail.com hotmail.es outlook.com outlook.es live.com msn.com yahoo.com yahoo.es ymail.com aol.com icloud.com me.com protonmail.com proton.me gmx.com gmx.net mail.com zoho.com yandex.com", fm, " ")
    for (i in fm) FREE[fm[i]] = 1
    # Marcas que se suplantan en Panamá (dominios oficiales verificados en 2026)
    # (nombre, palabras en el nombre del remitente, dominios oficiales, nombre que
    #  delata una imitación dentro de otro dominio)
    addbrand("Banco General", "banco general,bgeneral", "bgeneral.com,bgeneral.com.pa", "bgeneral")
    addbrand("Yappy", "yappy", "yappy.com.pa,bgeneral.com", "yappy")
    addbrand("Banistmo", "banistmo", "banistmo.com,banistmo.com.pa", "banistmo")
    addbrand("BAC Credomatic", "bac credomatic,credomatic", "baccredomatic.com,credomatic.com", "credomatic")
    addbrand("Caja de Ahorros", "caja de ahorros", "cajadeahorros.com.pa", "cajadeahorros")
    addbrand("Banco Nacional de Panamá", "banco nacional,banconal", "banconal.com.pa", "banconal")
    addbrand("Gobierno de Panamá", "ministerio publico,caja de seguro social,contraloria,dgi,ministerio de economia,policia nacional,tribunal electoral", ".gob.pa", "")
    addbrand("Microsoft", "microsoft,office 365,microsoft 365,outlook,onedrive,sharepoint", "microsoft.com,microsoftonline.com,office.com,office365.com,sharepoint.com,sharepointonline.com,live.com,outlook.com,office.net,microsoft365.com,microsoftstore.com,microsoftemail.com,azure.com", "microsoft,office365")
    addbrand("Google", "google", "google.com", "")
    addbrand("Apple", "apple,icloud", "apple.com", "")
    addbrand("PayPal", "paypal", "paypal.com,paypal.me,paypalobjects.com,paypal-communication.com,paypal-community.com", "paypal")
    addbrand("Amazon", "amazon", "amazon.com,amazon.es,amazon.com.mx", "")
    addbrand("DHL", "dhl", "dhl.com,dhl.de", "")
    addbrand("FedEx", "fedex", "fedex.com,fedex.com.pa", "fedex")
    addbrand("Netflix", "netflix", "netflix.com,netflix.net", "netflix")
    addbrand("DocuSign", "docusign", "docusign.net,docusign.com", "docusign")
    addbrand("WhatsApp", "whatsapp", "whatsapp.com,whatsapp.net", "whatsapp")
    addbrand("Meta / Facebook", "facebook,instagram", "facebookmail.com,facebook.com,instagram.com,meta.com", "")
    if (extra != "") { n = split(extra, el, "\n"); for (i = 1; i <= n; i++) if (split(el[i], ep, "|") == 3) addbrand(ep[1], tolower(ep[2]), tolower(ep[3]), "") }
}
{ sub(/\r$/, "") }
state == "H" || state == "PH" {
    if ($0 ~ /^[ \t]/ && cur != "") { if (length(curv) < (cur == "authentication-results" ? 65536 : 8192)) curv = curv " " substr($0, 1, 8192); next }
    hdr_store()
    if ($0 == "") { headers_done(); next }
    if (match($0, /^[^: \t]+[ \t]*:/)) { cur = tolower(substr($0, 1, RLENGTH - 1)); sub(/[ \t]+$/, "", cur); curv = substr($0, RLENGTH + 1, 8192) }
    next
}
{
    # ¿Es una frontera MIME (--boundary o --boundary--)? Búsqueda directa en
    # una tabla: recorrer todas las fronteras en cada línea era lento a propósito
    if (substr($0, 1, 2) == "--" && nbnd > 0 && length($0) > 2) {
        c = substr($0, 3); sub(/[ \t]+$/, "", c); closing = 0
        if (!(c in BLEVEL) && substr(c, length(c) - 1) == "--" && (substr(c, 1, length(c) - 2) in BLEVEL)) { c = substr(c, 1, length(c) - 2); closing = 1 }
        if (c in BLEVEL && (k = BLEVEL[c]) <= nbnd && bnd[k] == c) {
            if (state == "PB") part_end()
            if (closing) { for (j = k; j <= nbnd; j++) delete BLEVEL[bnd[j]]; nbnd = k - 1; state = "B" }
            else if (++nparts > 2000) { toomany = 1; for (j = k + 1; j <= nbnd; j++) delete BLEVEL[bnd[j]]; nbnd = k; state = "B" }      # tope de partes
            else { for (j = k + 1; j <= nbnd; j++) delete BLEVEL[bnd[j]]; nbnd = k; state = "PH"; delete PH; cur = "" }
            next
        }
    }
    if (state == "PB") part_line($0)
}
END {
    if (state == "H" || state == "PH") { hdr_store(); if (state == "H") headers_done() }
    if (state == "PB") part_end()
    # ¿Es un correo? (antes de leer H[...], que crearía las claves)
    print "H\tlooks_like_email\t" (nknown > 0 ? 1 : 0)

    from = H["from"]; faddr = addr_of(from); fname = name_of(from); fdom = dom_of(faddr)
    rt = addr_of(H["reply-to"]); rtdom = dom_of(rt)
    rp = addr_of(H["return-path"]); rpdom = dom_of(rp)
    subj = clean(hdrdec(H["subject"]))
    lsubj = norm(subj); lname = norm(fname)

    # Authentication-Results (RFC 8601): "servidor; spf=pass smtp.mailfrom=...; dkim=..."
    # Se quitan comentarios (...) y textos entre comillas, y solo cuenta
    # "método=resultado" AL PRINCIPIO de cada trozo: la dirección del remitente
    # (smtp.mailfrom=dmarc=pass...) la elige el atacante y no debe colarse.
    auth = strip_cfws(tolower(H["auth"]))
    # Cabecera mal formada (comillas o paréntesis sin cerrar): si el texto original
    # dice dmarc=fail, se respeta (nunca se pierde un fallo)
    if (auth !~ /dmarc[ \t]*=/ && tolower(H["auth"]) ~ /;[ \t\r\n]*dmarc[ \t]*=[ \t]*fail/) auth = auth "; dmarc=fail"
    na = split(auth, ap, ";")
    spf = dkim = dmarc = compauth = ""
    for (k = 1; k <= na; k++) {
        piece = ap[k]; sub(/^[ \t]+/, "", piece)
        if (!match(piece, /^(spf|dkim|dmarc|compauth)[ \t]*=[ \t]*[a-z]+/)) continue
        mth = piece; sub(/[ \t]*=.*$/, "", mth)
        res = substr(piece, 1, RLENGTH); sub(/^[^=]*=[ \t]*/, "", res)
        if (mth == "spf" && spf == "") spf = res
        else if (mth == "dkim") { if (dkim == "" || res == "pass") dkim = res }
        else if (mth == "dmarc") { if (dmarc == "" || res == "fail") dmarc = res }
        else if (mth == "compauth" && compauth == "") compauth = res
    }

    print "H\tfrom\t" trunc(clean(hdrdec(from)), 200)
    print "H\tfrom_addr\t" trunc(faddr, 120)
    fshow = fname; if (index(fshow, "@") || fshow ~ /[a-z0-9-]\.[a-z][a-z]/) gsub(/\./, "[.]", fshow)
    print "H\tfrom_name\t" trunc(fshow, 120)
    print "H\treply_to\t" trunc(rt, 120)
    print "H\treturn_path\t" trunc(rp, 120)
    print "H\tsubject\t" trunc(subj, 200)
    print "H\tdate\t" trunc(clean(H["date"]), 60)
    print "H\tdate_iso\t" isodate(H["date"])
    mid = H["message-id"]; gsub(/[<> \t]/, "", mid)
    print "H\tmessage_id\t" trunc(clean(mid), 200)
    print "H\tsender_ip\t" sender_ip
    print "H\tspf\t" spf
    print "H\tdkim\t" dkim
    print "H\tdmarc\t" dmarc
    print "H\tauth_headers\t" (nauth + 0)
    print "H\treceived\t" (nrecv + 0)

    if (faddr == "") flag("medium", "FROM-MISSING", "El correo no tiene un remitente válido en From", "T1566")

    # --- 1. Autenticación (la escribe el servidor que RECIBIÓ el correo) ---
    # Solo vale la cabecera Authentication-Results de más arriba: las de más
    # abajo pueden venir inventadas por el atacante dentro del propio correo.
    if (dmarc == "fail")
        flag("high", "AUTH-DMARC-FAIL", "El servidor que lo recibió comprobó que el remitente " dfd(fdom) " es FALSO (DMARC fail)", "T1566")
    else if (compauth == "fail")
        flag("high", "AUTH-COMPAUTH-FAIL", "Microsoft 365 no pudo verificar que el remitente " dfd(fdom) " sea real (compauth=fail)", "T1566")
    else if (dmarc == "" && spf ~ /^(fail|softfail)$/ && dkim != "pass")
        flag("medium", "AUTH-FAIL", "El remitente no pasó las comprobaciones (SPF " spf ", DKIM " (dkim == "" ? "ninguno" : dkim) ")", "T1566")
    if (nauth == 0)
        flag("info", "AUTH-NONE", "Sin cabecera de autenticación: no se puede saber si el remitente es real. Guarda el correo como .eml desde tu buzón (con todas las cabeceras)", "")
    if (toomany)
        flag("medium", "MIME-ABUSE", "El correo tiene una estructura anormal (demasiadas partes o anidamiento): es un truco para esquivar filtros", "T1027")
    if (nembed > 0)
        flag("info", "EMBEDDED", "Contiene " nembed " correo(s) reenviado(s) como adjunto: también se revisó su contenido", "")

    # --- 2. Suplantación de identidad ---
    if (fname ~ /[^ \t<>"]+@[^ \t<>"]+\.[a-z]+/) {
        fn = tolower(fname); match(fn, /[^ \t<>"()]+@[^ \t<>"()]+\.[a-z]+/); fnaddr = substr(fn, RSTART, RLENGTH)
        if (fnaddr != faddr)
            flag("high", "FROM-DISPLAY", "El nombre muestra una dirección (" dfa(fnaddr) ") distinta de la real (" dfa(faddr) ")", "T1656")
    }
    # Avisos de servicios (DocuSign, SharePoint, calendarios) responden al usuario real: es normal
    if (rt != "" && rtdom != "" && reg(rtdom) != reg(fdom) && reg(fdom) !~ /^(docusign\.net|docusign\.com|sharepointonline\.com|google\.com|calendly\.com|zoom\.us|microsoft\.com|dropbox\.com|linkedin\.com)$/) {
        if (fdom in FREE) flag("medium", "REPLYTO-DIFF", "Las respuestas no van al remitente sino a " dfa(rt), "T1656")
        else flag("high", "REPLYTO-DIFF", "Escribe desde " dfd(fdom) " pero las respuestas van a " dfa(rt) ": típico del fraude del jefe o del proveedor", "T1656")
    }
    if (fdom in FREE && (hasword(lname, "gerente") || hasword(lname, "gerencia") || hasword(lname, "director") || hasword(lname, "directora") || hasword(lname, "ceo") || hasword(lname, "presidente") || hasword(lname, "presidencia") || hasword(lname, "contabilidad") || hasword(lname, "finanzas") || hasword(lname, "tesoreria") || hasword(lname, "rrhh") || hasword(lname, "recursos humanos") || hasword(lname, "soporte") || hasword(lname, "sistemas") || hasword(lname, "administracion") || hasword(lname, "banco")))
        flag("medium", "FREEMAIL-ROLE", "Se presenta como \"" trunc(fname, 40) "\" pero escribe desde un correo gratuito (" dfd(fdom) ")", "T1656")
    if (fdom ~ /(^|\.)xn--/) flag("medium", "FROM-PUNY", "El remitente usa un dominio internacional (" dfd(fdom) "): puede imitar letras de otro dominio", "T1656")
    if (fname ~ /[\320\321]/ && fname ~ /[A-Za-z]/)
        flag("medium", "FROM-MIXED", "El nombre del remitente mezcla letras latinas con letras de otro alfabeto que se ven iguales (\"" trunc(fname, 40) "\")", "T1656")

    # Marcas: el NOMBRE del remitente dice "Banco General", pero el correo no
    # viene de su dominio. (Solo el nombre: un asunto como "Reunión de Teams" o
    # "Declaración DGI" es normal entre colegas.)
    for (i = 1; i <= nb; i++) {
        nk = split(bkw[i], kw, ",")
        hit = 0; ment = 0
        for (k = 1; k <= nk; k++) if (kw[k] != "") {
            if (hasword(lname, kw[k])) { hit = 1; bkwhit = kw[k] }
            if (hasword(lsubj, kw[k]) || hasword(alltext, kw[k])) ment = 1
        }
        if (hit || ment) brands = brands (brands == "" ? "" : ", ") bname[i]
        # Con remitente autenticado (DMARC pass) y dominio propio, el nombre debe
        # ser casi solo la marca: "Big Apple Imports" o "Tienda Luna - Pagos Yappy" no imitan a nadie
        if (hit && dmarc == "pass" && !(fdom in FREE) && nwords(lname) > nwords(bkwhit) + 1) hit = 0
        if (hit && fdom ~ /\.onmicrosoft\.com$/ && bname[i] == "Microsoft") {
            if (!tenant_mine(fdom)) flag("medium", "MS-TENANT", "Se presenta como Microsoft desde una cuenta de Microsoft 365 cualquiera (" dfd(fdom) "): Microsoft no avisa desde ahí", "T1656")
            hit = 0
        }
        if (hit && fdom != "" && (!brand_own(fdom, i) || fdom in FREE))
            flag("high", "BRAND-SPOOF", "Dice ser de " bname[i] " pero viene de " dfd(fdom) ", que no es un dominio de " bname[i], "T1656")
    }
    if (fdom ~ /[\200-\377]/ && (bl = brand_of_label(norm(fdom))))
        flag("critical", "BRAND-HOMOGLYPH", "El remitente " dfd(clean(fdom)) " se escribe con letras de otro alfabeto para parecer " bname[bl], "T1656")
    else if (fdom ~ /[\200-\377]/)
        flag("medium", "HOST-UNICODE", "El remitente usa un dominio con letras no latinas que imitan a las normales (" dfd(clean(fdom)) ")", "T1656")
    if ((bl = brand_lookalike(norm(fdom))))
        flag("high", "BRAND-LOOKALIKE", "El remitente usa " dfd(fdom) ", que lleva el nombre de " bname[bl] " pero no es suyo", "T1656")
    else if (rtdom != "" && (bl = brand_lookalike(rtdom)))
        flag("high", "BRAND-LOOKALIKE", "Las respuestas van a " dfd(rtdom) ", que lleva el nombre de " bname[bl] " pero no es suyo", "T1656")
    print "H\tbrands\t" brands

    # Dominios parecidos al tuyo (--mi-dominio)
    nm = split(mine, md, ",")
    for (k = 1; k <= nm; k++) {
        if (md[k] == "") continue
        if (fdom != "" && same_or_sub(fdom, md[k]) && (dmarc == "fail" || compauth == "fail"))
            flag("critical", "OWN-SPOOF", "Finge venir de TU dominio (" dfd(fdom) ") y el servidor comprobó que es falso", "T1656")
        if (lookalike(fdom, md[k])) flag("high", "LOOKALIKE", "El remitente usa " dfd(fdom) ", que imita a tu dominio " dfd(md[k]), "T1656")
        if (rtdom != "" && lookalike(rtdom, md[k])) flag("high", "LOOKALIKE-REPLY", "Las respuestas van a " dfd(rtdom) ", que imita a tu dominio " dfd(md[k]), "T1656")
        for (j = 1; j <= nhosts; j++) {
            if (lookalike(hostlist[j], md[k])) { flag("high", "LOOKALIKE-LINK", "Un enlace lleva a " dfd(hostlist[j]) ", que imita a tu dominio " dfd(md[k]), "T1566.002"); break }
            if (embeds(hostlist[j], md[k])) { flag("medium", "NAME-IN-LINK", "Un enlace usa el nombre de tu empresa dentro de otro dominio (" dfd(hostlist[j]) "): truco habitual de las páginas falsas de inicio de sesión", "T1566.002"); break }
        }
    }

    # Conversación secuestrada: responde a un hilo de proveedor@distribuidora-istmo
    # pero escribe desde distribuidora-ismto (no hace falta --mi-dominio)
    thr = H["in-reply-to"] " " H["references"]
    for (k = 0; k < 20 && match(thr, /@[a-z0-9.-]+\.[a-z]+/); k++) {
        td = tolower(substr(thr, RSTART + 1, RLENGTH - 1)); thr = substr(thr, RSTART + RLENGTH)
        if (fdom != "" && !(reg(td) in FREE) && lookalike(fdom, td)) { flag("high", "THREAD-LOOKALIKE", "Responde a una conversación con " dfd(reg(td)) " pero escribe desde " dfd(fdom) ", un dominio casi igual", "T1656"); break }
    }
    qt = alltext
    for (k = 0; k < 20 && match(qt, /(de|from):[^\n]{0,80}@[a-z0-9.-]+\.[a-z]+/); k++) {
        td = substr(qt, RSTART, RLENGTH); qt = substr(qt, RSTART + RLENGTH); sub(/^.*@/, "", td); td = tolower(td)
        if (fdom != "" && !(reg(td) in FREE) && lookalike(fdom, td)) { flag("high", "THREAD-LOOKALIKE", "Cita un correo anterior de " dfd(reg(td)) " pero escribe desde " dfd(fdom) ", un dominio casi igual", "T1656"); break }
    }

    # --- 3. El mensaje: urgencia, contraseñas, pagos, cambio de cuenta ---
    rawtxt = alltext
    nzw = gsub(/\342\200[\213-\215]|\357\273\277/, "", rawtxt)
    if (nzw > 3) flag("medium", "TEXT-ZW", "El texto esconde " nzw " caracteres invisibles entre las letras: truco para que los filtros no lean palabras como \"contraseña\"", "T1027")
    txt = lsubj " " norm(alltext)
    # Prisa: palabras fuertes siempre; las débiles ("expira", "24 horas") solo con una amenaza
    nu = split("urgente,urgencia,inmediatamente,hoy mismo,de inmediato,ultimo aviso,suspendida,suspendido,bloqueada,bloqueado,desactivada,caduca,asap,urgent,immediately,final notice,suspended", uw, ",")
    nwk = split("expira,vence hoy,24 horas,48 horas,inmediato", wk, ",")
    threat = (txt ~ /suspend|bloque|cancel|perder|eliminar|cerrar|desactiv|delete|lock/)
    nc = split("contrasena,clave de acceso,verificar su cuenta,verifique su cuenta,verifica tu cuenta,confirmar sus datos,confirme sus datos,confirma tus datos,actualizar sus datos,actualice sus datos,actualiza tus datos,iniciar sesion,inicie sesion,credenciales,codigo de verificacion,password,verify your account,sign in,log in", cw, ",")
    np = split("transferencia,ach,pago,factura,deposito,cuenta bancaria,wire transfer,invoice,payment,tarjeta de regalo,tarjetas de regalo,gift card,bitcoin,yappy", pw, ",")
    nx = split("cambio de cuenta,nueva cuenta bancaria,nuevos datos bancarios,cambiamos de banco,cambio de banco,actualizamos nuestros datos bancarios,actualizar los datos bancarios,datos bancarios actualizados,nuevas instrucciones de pago,nueva instruccion de pago,siguiente cuenta,cuenta anterior,fueron cerradas,ya no esta activa,new bank account,change of bank,updated bank details,new payment instructions", xw, ",")
    hu = hc = hp = hx = ""
    for (k = 1; k <= nu; k++) if (hasword(txt, uw[k])) { if (++chu <= 3) hu = hu (hu == "" ? "" : ", ") uw[k] }
    if (threat) for (k = 1; k <= nwk; k++) if (hasword(txt, wk[k])) { if (++chu <= 3) hu = hu (hu == "" ? "" : ", ") wk[k] }
    for (k = 1; k <= nc; k++) if (hasword(txt, cw[k])) { if (++chc <= 3) hc = hc (hc == "" ? "" : ", ") cw[k] }
    for (k = 1; k <= np; k++) if (hasword(txt, pw[k])) { if (++chp <= 3) hp = hp (hp == "" ? "" : ", ") pw[k] }
    for (k = 1; k <= nx; k++) if (hasword(txt, xw[k])) { if (++chx <= 3) hx = hx (hx == "" ? "" : ", ") xw[k] }
    if (hx != "" && hp != "") flag("high", "BEC-BANKCHANGE", "Pide pagar a una cuenta bancaria nueva o distinta (\"" hx "\"): es el fraude más caro para las empresas. Confírmalo por teléfono", "T1656")
    # ¿Hay enlaces a otro sitio que no sea el del remitente?
    extlink = 0
    for (j = 1; j <= nhosts; j++) if (reg(hostlist[j]) != reg(fdom) && redirector(hostlist[j], "") != 2 && reg(hostlist[j]) !~ /^(facebook|instagram|twitter|x|linkedin|youtube|tiktok|whatsapp)\.com$/) { extlink = 1; break }
    if (hu != "" && hc != "" && extlink)
        flag("high", "CRED-LINK", "Mete prisa (\"" hu "\"), pide tus datos de acceso (\"" hc "\") y te manda a otro sitio: el patrón clásico del robo de contraseñas", "T1566.002")
    else if (hu != "" && hc != "") flag("medium", "TEXT-CREDS", "Mete prisa (\"" hu "\") y pide datos de acceso (\"" hc "\")", "T1566")
    if (hu != "" && hp != "") flag("medium", "TEXT-PAY", "Mete prisa (\"" hu "\") y habla de dinero (\"" hp "\")", "T1566")
    # Tarjetas de regalo "del jefe" (texto típico escrito con IA)
    if (txt ~ /(estas disponible|estas libre|are you available|no puedo atender|no puedo hablar|estoy en (una )?reunion|i.m in a meeting)/ && txt ~ /(tarjeta|gift card|google play|itunes|apple card|steam|amazon|compra)/)
        flag((fdom in FREE) ? "high" : "medium", "BEC-GIFTCARD", "Pide un favor urgente (comprar tarjetas de regalo) a alguien que \"no puede atender llamadas\": estafa muy común", "T1656")
    # Estafa telefónica (sin enlaces): "se renovó por $499, llame al +1 8xx..."
    if (nhosts == 0 && txt ~ /(\+?1?[ (]*8[0-9][0-9][) .-]*[0-9][0-9][0-9][ .-]*[0-9][0-9][0-9][0-9]|\+ ?507[ -]?[0-9])/ && txt ~ /(\$ ?[0-9]|usd ?[0-9]|[0-9] ?usd|b\/\. ?[0-9])/ && txt ~ /(llame|llamar|comuniquese|contactenos|call us|call now|cancelar|cancel|reembolso|refund|renovacion|renewal|cargo|charged)/)
        flag((fdom in FREE || brands != "") ? "high" : "medium", "TOAD-CALLBACK", "Avisa de un cobro y pide que llames a un teléfono: si llamas, te piden datos o instalar un programa", "T1566.004")
    # Código QR para escanear (los enlaces van dentro de una imagen)
    if (txt ~ /(codigo qr|qr code|escanea|escanee|escanear|scan the)/ && nimg > 0 && nhosts == 0)
        flag((hu != "" || hc != "") ? "high" : "medium", "QR-CODE", "Pide escanear un código QR de una imagen: así el enlace no se puede revisar (quishing)", "T1566.002")
    # Inicio de sesión por código de dispositivo (robo de sesión de Microsoft 365)
    if (txt ~ /(microsoft\.com\/devicelogin|aka\.ms\/devicelogin|google\.com\/device)/)
        flag("high", "DEVICE-CODE", "Pide entrar en la página de \"código de dispositivo\": si pones ese código, el atacante queda conectado a tu cuenta", "T1528")
    # Formularios en servicios legítimos (Google Forms, Canva, Notion) pidiendo claves
    if (hc != "" && !(reg(fdom) ~ /^(google|microsoft|canva|notion)\.com$/))
        for (j = 1; j <= nhosts; j++) if (hostlist[j] ~ /(^|\.)(docs\.google\.com|forms\.gle|forms\.office\.com|sites\.google\.com|canva\.site|notion\.site|my\.canva\.site|webflow\.io|weebly\.com|wixsite\.com)$/) {
            flag("medium", "CRED-FREEHOST", "Pide datos de acceso y enlaza a una página gratuita (" dfd(hostlist[j]) "): las empresas no piden contraseñas así", "T1566.002"); break }
    if (lsubj ~ /^[ \t]*(re|rv|fw|fwd|res)[ \t]*:/ && H["in-reply-to"] == "" && H["references"] == "")
        flag("low", "FAKE-REPLY", "El asunto empieza por \"" substr(subj, 1, index(subj, ":")) "\" pero no responde a ningún correo anterior: imita una conversación", "T1566")
    # Cambio de cuenta + remitente que no es quien dice ser = fraude casi seguro
    if (("BEC-BANKCHANGE" in fseen || "BEC-GIFTCARD" in fseen) && ("REPLYTO-DIFF" in fseen || "FREEMAIL-ROLE" in fseen || "LOOKALIKE" in fseen || "LOOKALIKE-REPLY" in fseen || "THREAD-LOOKALIKE" in fseen || "BRAND-SPOOF" in fseen || "AUTH-DMARC-FAIL" in fseen))
        flag("critical", "BEC-CONFIRMED", "Pide dinero o un cambio de cuenta Y el remitente no es quien dice ser: no pagues sin confirmar por teléfono con un número conocido", "T1656")
    if (linkcap) flag("medium", "LINKS-TRUNCATED", "Tiene una cantidad anormal de enlaces (más de 5000): no se pudieron revisar todos", "T1027")
    if (ptrunc) flag("low", "TEXT-TRUNCATED", "El texto es muy largo: se revisó solo el principio", "")

    print "H\tlinks\t" (nlinks + 0)
    print "H\tlinks_listed\t" (nprint > 300 ? 300 : nprint + 0)
    print "H\tlink_hosts\t" (nhosts + 0)
    print "H\tattachments\t" (natt + 0)

    # --- Veredicto ---
    pts = 0
    for (i = 1; i <= nf; i++) {
        s = fsev[i]
        pts += (s == "critical") ? 50 : (s == "high") ? 25 : (s == "medium") ? 10 : (s == "low") ? 3 : 0
        if (s == "critical") crit = 1
        print "F\t" s "\t" fid[i] "\t" clean(ftxt[i]) (fcnt[fid[i]] > 1 ? " (y " fcnt[fid[i]] - 1 " más)" : "") "\t" fmit[i]
    }
    # Una sola señal media cuenta como sospechosa si no hay autenticación que la respalde
    # Pedir la contraseña y traer enlaces es sospechoso aunque el remitente esté
    # autenticado: el atacante también puede autenticar SU propio dominio
    own = 0; nm = split(mine, md, ","); for (k = 1; k <= nm; k++) if (md[k] != "" && fdom != "" && same_or_sub(fdom, md[k]) && dmarc == "pass") own = 1
    credlinks = (("TEXT-CREDS" in fseen) || ("CRED-FREEHOST" in fseen)) && nhosts > 0 && !own
    verdict = (crit || pts >= 50) ? "PELIGROSO" : (pts >= 15 || (pts >= 10 && dmarc != "pass") || credlinks) ? "SOSPECHOSO" : "SIN INDICIOS CLAROS"
    print "H\tverdict\t" verdict
    print "H\tpoints\t" pts
}
AWK

declare -A EH=(); E_F=(); E_U=(); E_T=(); E_SHA=()
EML_FILE=""

marcas_extra() {
    [[ -z "$MARCAS_FILE" ]] && return 0
    local line out="" n=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%$'\r'}
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        n=$((n + 1))
        # Formato: Nombre|palabra1,palabra2|dominio1,dominio2  (solo texto simple)
        [[ "$line" =~ ^[^|\\]{1,60}\|[^|\\]{1,300}\|[a-zA-Z0-9.,-]{3,300}$ ]] || die "$MARCAS_FILE, línea $n: usa el formato Nombre|palabras|dominios"
        out+="$line"$'\n'
    done < "$MARCAS_FILE"
    printf '%s' "$out"
}

run_eml() {
    local f=$1 raw rec size magic adir i sha
    [[ -f "$f" && -r "$f" ]] || die "no se puede leer el archivo $f"
    size=$(stat -c %s -- "$f")
    (( size > 26214400 )) && die "el correo pesa más de 25 MB; no parece un .eml normal"
    magic=$(head -c 4 -- "$f" | od -An -tx1 | tr -d ' \n')
    [[ "$magic" == d0cf11e0 ]] && die "es un archivo .msg de Outlook de escritorio. Abre ese mismo correo en outlook.office.com (Outlook en la web) y descárgalo desde ahí: ⋯ > Guardar como. Te dará un .eml"
    EML_FILE=$f
    local extra
    extra=$(marcas_extra) || exit 2      # el mensaje de error ya se mostró
    adir=$(mktemp -d) || die "no se pudo crear una carpeta temporal"
    raw=$(awk -v mine="$MY_DOMAINS" -v extra="$extra" -v adir="$adir" "$EML_AWK" < "$f") || { rm -rf -- "$adir"; die "no se pudo analizar $f"; }
    E_F=(); E_U=(); E_T=(); EH=(); E_SHA=()
    while IFS= read -r rec; do
        case "${rec%%$'\t'*}" in
            H) local k v; IFS=$'\t' read -r _ k v <<< "$rec"; EH[$k]=$v ;;
            F) E_F+=("${rec#*$'\t'}") ;;
            U) E_U+=("${rec#*$'\t'}") ;;
            T) E_T+=("${rec#*$'\t'}") ;;
        esac
    done <<< "$raw"
    # Huella SHA-256 de cada adjunto (para buscarla en VirusTotal o en el SIEM)
    for i in "${!E_T[@]}"; do
        sha=""
        [[ -f "$adir/$((i + 1)).b64" ]] && sha=$(base64 -di < "$adir/$((i + 1)).b64" 2>/dev/null | sha256sum | cut -c1-64)
        E_SHA+=("${sha:--}")
    done
    rm -rf -- "$adir"
    [[ "${EH[looks_like_email]:-0}" == 1 ]] || die "$(clean "$f") no parece un correo (.eml): no tiene cabeceras como From, Subject o Received"
    if [[ ${#E_F[@]} -gt 0 ]]; then
        mapfile -t E_F < <(printf '%s\n' "${E_F[@]}" | awk -F'\t' '{ r = ($1=="critical")?0:($1=="high")?1:($1=="medium")?2:($1=="low")?3:4; print r "\t" $0 }' | sort -s -t$'\t' -k1,1n | cut -f2-)
    fi
    [[ $ANON -eq 1 ]] && anonymize
    return 0
}

# --anonimizar: los informes se pueden compartir sin datos personales (Ley 81).
# Se ocultan los nombres y la parte de la dirección antes de la @; los
# dominios se mantienen porque son la clave del análisis.
anon_text() { sed -E 's/[A-Za-z0-9._%+=-]+@([A-Za-z0-9.[]|-])/***@\1/g' <<< "$1"; }
anonymize() {
    local k i
    for k in from_addr reply_to return_path message_id; do EH[$k]=$(anon_text "${EH[$k]:-}"); done
    EH[from]="[oculto]"; EH[from_name]="[oculto]"; EH[subject]="[oculto]"
    EML_FILE="[oculto]"
    for i in "${!E_F[@]}"; do E_F[i]=$(anon_text "${E_F[$i]}"); done
    for i in "${!E_U[@]}"; do E_U[i]=$(anon_text "${E_U[$i]}"); done
}

# Enlaces y direcciones "desactivados" para mostrarlos sin que se puedan pulsar
defang() { sed -e 's/^http/hxxp/I' -e 's/\./[.]/g' <<< "$1"; }
defang_addr() {
    local a=$1
    if [[ "$a" == *@* ]]; then printf '%s@%s' "${a%@*}" "$(defang "${a##*@}")"; else defang "$a"; fi
}

render_eml_text() {
    local c=${1:-0} b="" x="" g="" y="" col="" vc="" r sev id txt mitre url text host name ct bytes n=0
    [[ $c -eq 1 ]] && { b=$C_BLD; x=$C_RST; g=$C_GRY; y=$C_GRN; }
    printf '%scorreo-escudo v%s%s — ¿este correo es phishing?\n' "$b" "$VERSION" "$x"
    printf '%sArchivo: %s%s\n' "$g" "$(clean "$EML_FILE")" "$x"
    if [[ $c -eq 1 ]]; then case "${EH[verdict]}" in PELIGROSO) vc=$C_RED ;; SOSPECHOSO) vc=$C_YEL ;; *) vc=$C_GRN ;; esac; fi
    printf '\n  Veredicto: %s%s%s%s\n' "$vc" "$b" "${EH[verdict]}" "$x"
    case "${EH[verdict]}" in
        PELIGROSO)  printf '  No hagas clic en sus enlaces, no abras sus adjuntos y no respondas.\n' ;;
        SOSPECHOSO) printf '  Trátalo con cuidado: confirma con el remitente por otro medio (teléfono conocido).\n' ;;
        *)          printf '  No se ven señales claras de phishing. Eso no garantiza que sea seguro:\n  si pide dinero o contraseñas, confírmalo por otro medio.\n' ;;
    esac

    printf '\n%s== Datos del correo ==%s\n' "$b" "$x"
    printf '  %-14s %s%s\n' "De:" "${EH[from_name]:+${EH[from_name]} }" "<$(defang_addr "${EH[from_addr]:-?}")>"
    [[ -n "${EH[reply_to]:-}" ]] && printf '  %-14s %s\n' "Responder a:" "$(defang_addr "${EH[reply_to]}")"
    printf '  %-14s %s\n' "Asunto:" "${EH[subject]:-}"
    [[ -n "${EH[date]:-}" ]] && printf '  %-14s %s\n' "Fecha:" "${EH[date]}"
    if [[ "${EH[auth_headers]:-0}" -gt 0 ]]; then
        printf '  %-14s SPF %s · DKIM %s · DMARC %s %s(según el servidor que lo recibió)%s\n' "Autenticación:" \
            "${EH[spf]:-?}" "${EH[dkim]:-?}" "${EH[dmarc]:-?}" "$g" "$x"
    else
        printf '  %-14s %s(sin datos: el archivo no trae las cabeceras del servidor)%s\n' "Autenticación:" "$g" "$x"
    fi
    printf '  %-14s %s enlaces a %s sitios · %s adjuntos\n' "Contenido:" "${EH[links]:-0}" "${EH[link_hosts]:-0}" "${EH[attachments]:-0}"

    printf '\n%s== Señales de peligro ==%s\n' "$b" "$x"
    if [[ ${#E_F[@]} -eq 0 ]]; then
        printf '  %sNinguna encontrada.%s\n' "$y" "$x"
    else
        for r in "${E_F[@]}"; do
            IFS=$'\t' read -r sev id txt mitre <<< "$r"
            [[ $c -eq 1 ]] && col=$(sev_color "$sev")
            [[ $DETAIL -eq 1 ]] || mitre=""
            printf '  %s%s%s %-16s %s%s\n' "$col" "$(sev_tag "$sev")" "$x" "$id" "$txt" "${mitre:+ $g(MITRE $mitre)$x}"
        done
    fi

    if [[ ${#E_U[@]} -gt 0 ]]; then
        printf '\n%s== Enlaces (desactivados: no los copies al navegador) ==%s\n' "$b" "$x"
        for r in "${E_U[@]}"; do
            n=$((n + 1)); [[ $n -gt 12 ]] && { printf '  … y %d más (ver --format json)\n' $(( ${#E_U[@]} - 12 )); break; }
            IFS=$'\t' read -r url text host <<< "$r"
            [[ "$text" == - ]] && text=""
            printf '  %s%s\n' "$(defang "$url")" "${text:+   $g← el texto dice: \"$text\"$x}"
        done
    fi
    if [[ ${#E_T[@]} -gt 0 ]]; then
        n=0
        printf '\n%s== Adjuntos (no se han abierto) ==%s\n' "$b" "$x"
        for r in "${E_T[@]}"; do
            IFS=$'\t' read -r name ct bytes _ <<< "$r"
            [[ "$ct" == - ]] && ct="tipo desconocido"
            printf '  %s  %s(%s, ~%s KB)%s\n' "$name" "$g" "$ct" "$(( (bytes + 1023) / 1024 ))" "$x"
            n=$((n + 1)); [[ $DETAIL -eq 1 && "${E_SHA[n-1]:--}" != - ]] && printf '     %sSHA-256 %s%s\n' "$g" "${E_SHA[n-1]}" "$x"
        done
    fi

    if [[ "${EH[verdict]}" != "SIN INDICIOS CLAROS" ]]; then
        printf '\n%s== Qué hacer ==%s\n' "$b" "$x"
        printf '  1. No respondas, no hagas clic y no abras los adjuntos.\n'
        printf '  2. Si habla de dinero o de cambiar una cuenta, llama a esa persona o empresa a un número\n     que ya tenías guardado. Nunca al que viene en el correo.\n'
        printf '  3. Reenvíaselo a quien te lleva el correo (tu técnico o tu proveedor) y márcalo como phishing:\n     en Outlook, botón Informar > Phishing; en Gmail, ⋮ > Denunciar phishing.\n'
        printf '  4. ¿Ya pusiste tu contraseña? Cámbiala ya y activa la verificación en dos pasos.\n'
        printf '  5. ¿Ya hiciste la transferencia? Llama a tu banco AHORA para intentar frenarla y pon la\n     denuncia en el Ministerio Público. Las primeras horas cuentan.\n'
    fi
    [[ $DETAIL -eq 1 ]] || printf '%s(Con --detalle verás las técnicas MITRE ATT&CK y las huellas SHA-256 de los adjuntos.)%s\n' "$g" "$x"
    echo
}

render_eml_json() {
    local i code
    code=$(case "${EH[verdict]}" in PELIGROSO) echo dangerous ;; SOSPECHOSO) echo suspicious ;; *) echo clean ;; esac)
    printf '{\n  "tool": "correo-escudo",\n  "version": "%s",\n  "schema_version": 2,\n  "type": "email",\n' "$VERSION"
    printf '  "file": "%s",\n  "generated": "%s",\n' "$(json_esc "$EML_FILE")" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "verdict": "%s",\n  "verdict_code": "%s",\n  "points": %d,\n' "$(json_esc "${EH[verdict]}")" "$code" "${EH[points]:-0}"
    printf '  "message_id": "%s",\n  "sender_ip": "%s",\n' "$(json_esc "${EH[message_id]:-}")" "$(json_esc "${EH[sender_ip]:-}")"
    printf '  "from_name": "%s",\n' "$(json_esc "${EH[from_name]:-}")"
    printf '  "from": "%s",\n  "from_address": "%s",\n  "reply_to": "%s",\n  "return_path": "%s",\n' \
        "$(json_esc "${EH[from]:-}")" "$(json_esc "${EH[from_addr]:-}")" "$(json_esc "${EH[reply_to]:-}")" "$(json_esc "${EH[return_path]:-}")"
    printf '  "subject": "%s",\n  "date": "%s",\n  "date_iso": "%s",\n' "$(json_esc "${EH[subject]:-}")" "$(json_esc "${EH[date]:-}")" "$(json_esc "${EH[date_iso]:-}")"
    printf '  "authentication": {"spf": "%s", "dkim": "%s", "dmarc": "%s"},\n' "$(json_esc "${EH[spf]:-}")" "$(json_esc "${EH[dkim]:-}")" "$(json_esc "${EH[dmarc]:-}")"
    printf '  "brands_mentioned": "%s",\n' "$(json_esc "${EH[brands]:-}")"
    printf '  "links_total": %d,\n  "links_listed": %d,\n' "${EH[links]:-0}" "${EH[links_listed]:-0}"
    # Las filas se convierten a JSON con awk en una sola pasada: con cientos de
    # enlaces, un subproceso por campo tardaba varios segundos
    printf '  "findings": ['
    [[ ${#E_F[@]} -gt 0 ]] && printf '%s\n' "${E_F[@]}" | json_rows finding
    printf '],\n  "links": ['
    [[ ${#E_U[@]} -gt 0 ]] && printf '%s\n' "${E_U[@]}" | json_rows link
    printf '],\n  "attachments": ['
    if [[ ${#E_T[@]} -gt 0 ]]; then
        for i in "${!E_T[@]}"; do printf '%s\t%s\n' "${E_T[i]}" "${E_SHA[i]:--}"; done | json_rows attachment
    fi
    printf ']\n}\n'
}

json_rows() {
    awk -F'\t' -v kind="$1" '
        function esc(v) { gsub(/[\001-\037\177]/, " ", v); gsub(/\\/, "\\\\", v); gsub(/"/, "\\\"", v); return v }
        function un(v) { return v == "-" ? "" : v }
        function dfu(u) { sub(/^[Hh][Tt][Tt][Pp]/, "hxxp", u); gsub(/\./, "[.]", u); return u }
        { printf "%s\n    ", (NR > 1 ? "," : "") }
        kind == "finding"    { pts = ($1 == "critical") ? 50 : ($1 == "high") ? 25 : ($1 == "medium") ? 10 : ($1 == "low") ? 3 : 0
                               printf "{\"severity\": \"%s\", \"id\": \"%s\", \"points\": %d, \"title\": \"%s\", \"mitre\": \"%s\"}", esc($1), esc($2), pts, esc($3), esc($4) }
        kind == "link"       { printf "{\"url\": \"%s\", \"url_defanged\": \"%s\", \"text\": \"%s\", \"host\": \"%s\"}", esc($1), esc(dfu($1)), esc(un($2)), esc(un($3)) }
        kind == "attachment" { printf "{\"name\": \"%s\", \"type\": \"%s\", \"bytes\": %d, \"sha256\": \"%s\"}", esc($1), esc(un($2)), $3, esc(un($5)) }
        END { if (NR > 0) printf "\n  " }'
}

# Código de salida de un correo: 0 sin indicios · 1 sospechoso · 3 peligroso
# (con --fail-on critical, solo PELIGROSO cuenta)
eml_code() {
    case "${EH[verdict]}" in
        PELIGROSO) echo 3 ;;
        SOSPECHOSO) [[ "$FAIL_ON" == critical ]] && echo 0 || echo 1 ;;
        *) echo 0 ;;
    esac
}

# Uno o muchos correos (archivos, carpetas o "-" para la entrada estándar).
# Con varios: una línea por correo en texto, o JSON Lines con --format json.
# Recorta a n caracteres (sin partir letras con tilde) y marca el corte con "…"
cutw() {
    local LC_ALL=C.UTF-8 s=$1 n=$2
    (( ${#s} > n )) && s="${s:0:n-1}…"
    printf '%s' "$s"
}

run_many() {
    local files=() t f code worst=0 errs=0 tmpin="" out line n=0
    for t in "${TARGETS[@]}"; do
        if [[ "$t" == - ]]; then
            tmpin=$(mktemp) || die "no se pudo crear un archivo temporal"
            head -c 26214401 > "$tmpin"; files+=("$tmpin")
        elif [[ -d "$t" ]]; then
            while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$t" -maxdepth 1 -type f -iname '*.eml' -print0 | sort -z)
        else
            files+=("$t")
        fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "no hay ningún archivo .eml que analizar"
    if [[ ${#files[@]} -eq 1 ]]; then
        run_eml "${files[0]}"
        [[ -n "$tmpin" ]] && { rm -f -- "$tmpin"; [[ $ANON -eq 1 ]] || EML_FILE="(entrada estándar)"; }
        emit render_eml_text render_eml_json
        code=$(eml_code); exit "$code"
    fi
    out=$(
        for f in "${files[@]}"; do
            n=$((n + 1))
            # Cada correo en un subproceso: uno dañado no detiene el lote
            line=$( ( exec 3>&1; run_eml "$f" 2>&3 >/dev/null
                      [[ "$f" == "$tmpin" && $ANON -eq 0 ]] && EML_FILE="(entrada estándar)"
                      if [[ "$FORMAT" == json ]]; then render_eml_json | tr '\n' ' '; echo
                      else
                          ids=$(printf '%s\n' "${E_F[@]}" | cut -f2 | grep -v '^$' | head -n 6 | paste -sd, -)
                          printf '%-20s %-34s %-36s %s\n' "${EH[verdict]}" "$(cutw "$(clean "$(basename -- "$EML_FILE")")" 34)" "$(cutw "${EH[from_addr]:-?}" 36)" "${ids:--}"
                      fi
                      echo "@@CODE=$(eml_code)" ) )
            code=${line##*@@CODE=}; line=${line%@@CODE=*}
            if [[ ! "$code" =~ ^[0-9]+$ ]]; then
                errs=1
                if [[ "$FORMAT" == json ]]; then printf '{"tool": "correo-escudo", "type": "email", "file": "%s", "error": "%s"}\n' "$(json_esc "$f")" "$(json_esc "${line#Error: }")"
                else printf '%-20s %-34s %s\n' "ERROR" "$(cutw "$(clean "$(basename -- "$f")")" 34)" "$(cutw "$(clean "${line#Error: }")" 80)"; fi
                continue
            fi
            printf '%s' "$line"
            (( code > worst )) && worst=$code
        done
        echo "@@FIN=$worst,$errs"
    )
    [[ -n "$tmpin" ]] && rm -f -- "$tmpin"
    local st=${out##*@@FIN=}; out=${out%@@FIN=*}
    worst=${st%,*}; errs=${st#*,}
    out=${out%$'\n'}
    if [[ "$FORMAT" != json ]]; then
        out=$(printf 'correo-escudo v%s — %d correos\n\n%-20s %-34s %-36s %s\n%s' "$VERSION" "${#files[@]}" "Veredicto" "Archivo" "Remitente" "Señales" "$out")
    fi
    if [[ -n "$OUTPUT_FILE" ]]; then printf '%s\n' "$out" | safe_write "$OUTPUT_FILE"; printf 'Informe guardado en %s (permisos 600)\n' "$OUTPUT_FILE" >&2
    else printf '%s\n' "$out"; fi
    (( worst > 0 )) && exit "$worst"
    (( errs )) && exit 2
    exit 0
}

# =============================================================================
#  Programa principal
# =============================================================================
check_dest() {
    local dest=$1 dir
    [[ -L "$dest" ]] && die "$dest es un enlace simbólico; por seguridad no se escribe en él"
    [[ -d "$dest" ]] && die "$dest es un directorio"
    dir=$(dirname -- "$dest")
    [[ -d "$dir" && -w "$dir" ]] || die "no se puede escribir en el directorio $dir"
}
safe_write() {
    local dest=$1 tmp
    tmp=$(mktemp -- "$(dirname -- "$dest")/.correo-escudo.XXXXXX") || die "no se puede escribir en $(dirname -- "$dest")"
    # Si el disco se llena o falla la escritura, no se reemplaza el informe anterior
    cat > "$tmp" || { rm -f -- "$tmp"; die "no se pudo escribir $dest (¿disco lleno?)"; }
    mv -f -T -- "$tmp" "$dest" || { rm -f -- "$tmp"; die "no se pudo guardar $dest"; }
}

parse_args() {
    local d
    [[ $# -eq 0 ]] && { usage; exit 2; }
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -v|--version) echo "correo-escudo v${VERSION}"; exit 0 ;;
        dominio|lista|analizar) COMMAND=$1; shift ;;
        *) printf 'Comando desconocido: %s\n\n' "$(clean "$1")" >&2; usage >&2; exit 2 ;;
    esac
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --selector)   [[ "${2:-}" =~ ^[A-Za-z0-9._-]{1,63}$ ]] || die "--selector: solo letras, números, . _ -"; SELECTORS+=("$2"); shift 2 ;;
            --resolver)   [[ "${2:-}" =~ ^[0-9A-Fa-f:.]{2,45}$ ]] || die "--resolver necesita una IP"; RESOLVER=$2; shift 2 ;;
            --no-https)   NO_HTTPS=1; shift ;;
            --mi-dominio) [[ -n "${2:-}" ]] || die "--mi-dominio necesita un dominio"
                          IFS=, read -r -a _doms <<< "$2"
                          for d in "${_doms[@]}"; do d=$(norm_domain "$d"); valid_domain "$d" || die "--mi-dominio: '$(clean "$d")' no es un dominio"; MY_DOMAINS+="${MY_DOMAINS:+,}$d"; done
                          shift 2 ;;
            --marcas)     [[ -r "${2:-}" && -f "${2:-}" ]] || die "--marcas: no se puede leer ${2:-}"; MARCAS_FILE=$2; shift 2 ;;
            --format)     [[ "${2:-}" =~ ^(text|json)$ ]] || die "--format debe ser text o json"; FORMAT=$2; shift 2 ;;
            -o|--output)  [[ -n "${2:-}" ]] || die "--output necesita un archivo"; OUTPUT_FILE=$2; shift 2 ;;
            --fail-on)    [[ "${2:-}" =~ ^(low|medium|high|critical)$ ]] || die "--fail-on: low|medium|high|critical"; FAIL_ON=$2; shift 2 ;;
            --no-color)   USE_COLOR=0; shift ;;
            --anonimizar) ANON=1; shift ;;
            --detalle)    DETAIL=1; shift ;;
            -h|--help)    usage; exit 0 ;;
            -)            TARGETS+=("-"); shift ;;
            --)           shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
            -*)           die "opción desconocida: $(clean "$1")" ;;
            *)            TARGETS+=("$1"); shift ;;
        esac
    done
    [[ ${#TARGETS[@]} -gt 0 ]] || die "falta el $(case $COMMAND in dominio) echo dominio ;; lista) echo archivo con la lista ;; *) echo archivo .eml ;; esac)"
    [[ "$COMMAND" != analizar && ${#TARGETS[@]} -gt 1 ]] && die "sobra un argumento: $(clean "${TARGETS[1]}")"
    TARGET=${TARGETS[0]}
    [[ -n "$OUTPUT_FILE" ]] && check_dest "$OUTPUT_FILE"
    if [[ "$COMMAND" != analizar && -z "$DNS_FILE" ]]; then
        have dig || die "se necesita 'dig': sudo apt install dnsutils"
    fi
    return 0
}

emit() {   # emit FUNCIÓN_TEXTO FUNCIÓN_JSON
    local fn=$1 arg=$USE_COLOR
    [[ "$FORMAT" == json ]] && { fn=$2; arg=""; }
    if [[ -n "$OUTPUT_FILE" ]]; then
        [[ -n "$arg" ]] && arg=0
        "$fn" ${arg:+"$arg"} | safe_write "$OUTPUT_FILE"
        [[ ${PIPESTATUS[1]} -eq 0 ]] || exit 2       # safe_write ya explicó el error
        printf 'Informe guardado en %s (permisos 600)\n' "$OUTPUT_FILE" >&2
    else
        "$fn" ${arg:+"$arg"}
    fi
}

main() {
    parse_args "$@"
    setup_colors
    case "$COMMAND" in
        dominio)
            run_domain "$TARGET"
            emit render_domain_text render_domain_json
            (( WORST >= $(sev_num "$FAIL_ON") )) && exit 1
            [[ ${#INCOMPLETE[@]} -gt 0 ]] && exit 2
            exit 0 ;;
        lista)
            [[ -f "$TARGET" && -r "$TARGET" ]] || die "no se puede leer $TARGET"
            local out
            out=$(run_list "$TARGET" && echo "@@ESTADO=$LIST_WORST,$LIST_ERR") || exit 2
            local st=${out##*@@ESTADO=}; out=${out%@@ESTADO=*}
            LIST_WORST=${st%,*}; LIST_ERR=${st#*,}
            if [[ -n "$OUTPUT_FILE" ]]; then printf '%s' "$out" | safe_write "$OUTPUT_FILE"; printf 'Informe guardado en %s (permisos 600)\n' "$OUTPUT_FILE" >&2
            else printf '%s' "$out"; fi
            (( LIST_WORST >= $(sev_num "$FAIL_ON") )) && exit 1
            (( LIST_ERR )) && exit 2
            exit 0 ;;
        analizar)
            run_many ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

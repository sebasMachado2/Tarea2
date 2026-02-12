#!/bin/ash

set -u

KEA_PKG="kea-dhcp4"
KEA_SVC="kea-dhcp4"
KEA_CONF="/etc/kea/kea-dhcp4.conf"
KEA_LEASES="/var/lib/kea/kea-leases4.csv"
STATE_FILE="/etc/kea/kea_menu_state.env"

pausa() { printf "\nPresiona Enter para continuar..." >&2; read -r _; }
es_root() { [ "$(id -u)" -eq 0 ]; }
requiere_root() { es_root || { echo "ERROR: Ejecuta como root. Ej: sudo sh $0" >&2; exit 1; }; }
existe_comando() { command -v "$1" >/dev/null 2>&1; }

asegurar_herramientas_ip() {
  if ! existe_comando ip; then
    echo "Instalando iproute2 (comando ip)..." >&2
    apk add --no-cache iproute2 >&2 || return 1
  fi
  return 0
}

ip_a_vars() {
  ip="$1"; pref="$2"
  IFS='.' read -r a b c d <<EOF
$ip
EOF
  eval "${pref}1=\${a:-}"; eval "${pref}2=\${b:-}"; eval "${pref}3=\${c:-}"; eval "${pref}4=\${d:-}"
}

es_octeto() {
  o="$1"
  echo "$o" | grep -Eq '^[0-9]+$' || return 1
  [ "$o" -ge 0 ] 2>/dev/null && [ "$o" -le 255 ] 2>/dev/null
}

es_ipv4_valida() {
  ip="$1"
  case "$ip" in
    0.0.0.0|255.255.255.255) return 1 ;;
  esac
  echo "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
  ip_a_vars "$ip" "o"
  es_octeto "${o1:-}" && es_octeto "${o2:-}" && es_octeto "${o3:-}" && es_octeto "${o4:-}"
}

comparar_ip() {
  ip1="$1"; ip2="$2"
  ip_a_vars "$ip1" "a"
  ip_a_vars "$ip2" "b"
  for k in 1 2 3 4; do
    eval x=\$a$k; eval y=\$b$k
    [ "$x" -lt "$y" ] && { echo -1; return; }
    [ "$x" -gt "$y" ] && { echo 1; return; }
  done
  echo 0
}

sumar_uno_ip() {
  ip="$1"
  ip_a_vars "$ip" "t"
  a=${t1}; b=${t2}; c=${t3}; d=${t4}

  d=$((d+1))
  if [ "$d" -ge 256 ]; then d=0; c=$((c+1)); fi
  if [ "$c" -ge 256 ]; then c=0; b=$((b+1)); fi
  if [ "$b" -ge 256 ]; then b=0; a=$((a+1)); fi
  echo "$a.$b.$c.$d"
}

detectar_prefijo_por_ip() {
  ip="$1"
  ip_a_vars "$ip" "h"
  a=${h1}; b=${h2}
  if [ "$a" -eq 10 ]; then echo 8; return; fi
  if [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; then echo 12; return; fi
  if [ "$a" -eq 192 ] && [ "$b" -eq 168 ]; then echo 24; return; fi
  echo 24
}

prefijo_a_mascara() {
  p="$1"
  o1=0; o2=0; o3=0; o4=0
  for idx in 1 2 3 4; do
    if [ "$p" -ge 8 ]; then
      oct=255; p=$((p-8))
    elif [ "$p" -gt 0 ]; then
      oct=$((256 - (1 << (8 - p)))); p=0
    else
      oct=0
    fi
    eval o$idx=$oct
  done
  echo "$o1.$o2.$o3.$o4"
}

direccion_red() {
  ip="$1"; mask="$2"
  ip_a_vars "$ip" "i"
  ip_a_vars "$mask" "m"
  n1=$(( i1 & m1 )); n2=$(( i2 & m2 )); n3=$(( i3 & m3 )); n4=$(( i4 & m4 ))
  echo "$n1.$n2.$n3.$n4"
}

direccion_broadcast() {
  net="$1"; mask="$2"
  ip_a_vars "$net" "n"
  ip_a_vars "$mask" "m"
  inv1=$((255 - m1)); inv2=$((255 - m2)); inv3=$((255 - m3)); inv4=$((255 - m4))
  b1=$(( n1 | inv1 )); b2=$(( n2 | inv2 )); b3=$(( n3 | inv3 )); b4=$(( n4 | inv4 ))
  echo "$b1.$b2.$b3.$b4"
}

misma_subred() {
  ip1="$1"; ip2="$2"; mask="$3"
  n1="$(direccion_red "$ip1" "$mask")"
  n2="$(direccion_red "$ip2" "$mask")"
  [ "$n1" = "$n2" ]
}

leer_requerido() {
  prompt="$1"
  while :; do
    printf "%s: " "$prompt" >&2
    read -r v
    [ -n "${v:-}" ] && { echo "$v"; return; }
    echo "No puede ir vacio." >&2
  done
}

leer_ipv4_requerida() {
  prompt="$1"
  while :; do
    printf "%s: " "$prompt" >&2
    read -r ip
    if es_ipv4_valida "${ip:-}"; then echo "$ip"; return; fi
    echo "IPv4 invalida (o 0.0.0.0 / 255.255.255.255 no permitido)." >&2
  done
}

leer_ipv4_opcional() {
  prompt="$1 (opcional, Enter para omitir)"
  while :; do
    printf "%s: " "$prompt" >&2
    read -r ip
    [ -z "${ip:-}" ] && { echo ""; return; }
    if es_ipv4_valida "$ip"; then echo "$ip"; return; fi
    echo "IPv4 invalida." >&2
  done
}

leer_dns_opcional() {
  prompt="$1 (opcional, varios separados por coma)"
  while :; do
    printf "%s: " "$prompt" >&2
    read -r line
    [ -z "${line:-}" ] && { echo ""; return; }
    dns_list=$(echo "$line" | tr ',' ' ')
    ok=1
    for d in $dns_list; do
      es_ipv4_valida "$d" || { ok=0; break; }
    done
    [ "$ok" -eq 1 ] && { echo "$dns_list"; return; }
    echo "DNS invalido. Ej: 192.168.100.1 8.8.8.8 o 192.168.100.1,8.8.8.8" >&2
  done
}

si_no() {
  q="$1"
  while :; do
    printf "%s [s/n]: " "$q" >&2
    read -r a
    case "${a:-}" in
      s|S|si|SI|Sí|sí) return 0 ;;
      n|N|no|NO) return 1 ;;
      *) echo "Responde s o n." >&2 ;;
    esac
  done
}

elegir_interfaz() {
  asegurar_herramientas_ip || return 1
  echo "Interfaces disponibles:" >&2

  ifaces=$(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$')

  i=1
  for it in $ifaces; do
    ip4=$(ip -4 -o addr show dev "$it" 2>/dev/null | awk '{print $4}' | head -n1)
    st=$(ip -o link show dev "$it" 2>/dev/null | awk '{print $9}')
    printf "  %d) %s   (%s)   IPv4:%s\n" "$i" "$it" "${st:-?}" "${ip4:-none}" >&2
    i=$((i+1))
  done

  while :; do
    printf "Elige el numero de la interfaz para la red interna DHCP: " >&2
    read -r n
    sel=$(echo "$ifaces" | awk -v n="$n" 'NR==n{print; exit}')
    [ -n "${sel:-}" ] && { echo "$sel"; return; }
    echo "Opcion invalida." >&2
  done
}

esta_instalado() { apk info -e "$KEA_PKG" >/dev/null 2>&1; }

opcion_1_verificar() {
  echo "== Verificar instalacion =="
  if esta_instalado; then echo "DHCPv4 ($KEA_PKG) esta INSTALADO."
  else echo " DHCPv4 ($KEA_PKG) NO esta instalado."
  fi
  pausa
}

opcion_2_instalar() {
  echo "== Instalar DHCP =="
  if esta_instalado; then
    echo "Ya esta instalado."
    if si_no "Quieres reinstalarlo?"; then
      echo "Reinstalando..."
      apk del "$KEA_PKG" >/dev/null 2>&1 || true
      apk add --no-cache "$KEA_PKG" || { echo "ERROR instalando paquete."; pausa; return; }
    else
      echo "No se reinstalo."
      pausa; return
    fi
  else
    apk add --no-cache "$KEA_PKG" || { echo "ERROR instalando paquete."; pausa; return; }
  fi

  rc-update add "$KEA_SVC" default >/dev/null 2>&1 || true
  rc-service "$KEA_SVC" start >/dev/null 2>&1 || true
  echo "Listo: DHCP instalado."
  pausa
}

guardar_interfaces() {
  iface="$1"; addr="$2"; mask="$3"
  mkdir -p /etc/network >/dev/null 2>&1 || true
  file="/etc/network/interfaces"
  tmp="/tmp/interfaces.$$"

  if [ -f "$file" ]; then
    awk -v IF="$iface" '
      BEGIN{skip=0}
      $1=="auto" && $2==IF {skip=1; next}
      $1=="iface" && $2==IF {skip=1; next}
      skip==1 { if ($1=="auto" || $1=="iface") {skip=0} }
      skip==0 {print}
    ' "$file" > "$tmp"
  else
    cat > "$tmp" <<EOF
auto lo
iface lo inet loopback

EOF
  fi

  cat >> "$tmp" <<EOF

auto $iface
iface $iface inet static
  address $addr
  netmask $mask
EOF

  mv "$tmp" "$file"
}

opcion_3_configurar() {
  echo "== Configurar ambito =="
  if ! esta_instalado; then echo "Primero instala DHCP."; pausa; return; fi

  IFACE="$(elegir_interfaz)" || { echo "No se pudo seleccionar interfaz."; pausa; return; }

  SCOPE_NAME="$(leer_requerido "Nombre del ambito ")"
  echo "$SCOPE_NAME" | grep -Eq '^[A-Za-z0-9 _-]{1,48}$' || { echo "Nombre invalido."; pausa; return; }

  START_IP="$(leer_ipv4_requerida "Rango inicial")"
  PREFIX="$(detectar_prefijo_por_ip "$START_IP")"
  MASK="$(prefijo_a_mascara "$PREFIX")"
  NET="$(direccion_red "$START_IP" "$MASK")"
  BCAST="$(direccion_broadcast "$NET" "$MASK")"
  SUBNET_CIDR="$NET/$PREFIX"

  echo "Mascara detectada por IP inicial: $MASK (/$PREFIX)"
  echo "Subred calculada: $SUBNET_CIDR"

  [ "$START_IP" = "$NET" ] && { echo "ERROR: La IP inicial no puede ser la direccion de red ($NET)."; pausa; return; }
  [ "$START_IP" = "$BCAST" ] && { echo "ERROR: La IP inicial no puede ser broadcast ($BCAST)."; pausa; return; }

  END_IP="$(leer_ipv4_requerida "Rango final")"
  if ! misma_subred "$START_IP" "$END_IP" "$MASK"; then
    echo "ERROR: IP inicial y final NO estan en la misma subred ($SUBNET_CIDR)."
    pausa; return
  fi
  [ "$END_IP" = "$NET" ] && { echo "ERROR: La IP final no puede ser la direccion de red ($NET)."; pausa; return; }
  [ "$END_IP" = "$BCAST" ] && { echo "ERROR: La IP final no puede ser broadcast ($BCAST)."; pausa; return; }

  cmp="$(comparar_ip "$START_IP" "$END_IP")"
  [ "$cmp" -lt 0 ] || { echo "ERROR: El rango final debe ser MAYOR que el inicial."; pausa; return; }

  POOL_START_IP="$(sumar_uno_ip "$START_IP")"

  if ! misma_subred "$START_IP" "$POOL_START_IP" "$MASK"; then
    echo "ERROR: La IP inicial es demasiado alta. Usa otra IP inicial."
    pausa; return
  fi
  cmp2="$(comparar_ip "$POOL_START_IP" "$END_IP")"
  [ "$cmp2" -le 0 ] || { echo "ERROR: END debe ser >= $POOL_START_IP"; pausa; return; }

  GATEWAY="$(leer_ipv4_opcional "Gateway")"
  if [ -n "${GATEWAY:-}" ] && ! misma_subred "$START_IP" "$GATEWAY" "$MASK"; then
    echo "ERROR: El gateway debe estar en la misma subred ($SUBNET_CIDR)."
    pausa; return
  fi

  DNS_LIST="$(leer_dns_opcional "DNS")"

  while :; do
    printf "Tiempo de concesion en minutos (ej: 60): " >&2
    read -r LEASE_MIN
    echo "${LEASE_MIN:-}" | grep -Eq '^[0-9]+$' || { echo "Debe ser entero." >&2; continue; }
    [ "$LEASE_MIN" -ge 1 ] || { echo "Debe ser >= 1." >&2; continue; }
    break
  done
  LEASE_SEC=$((LEASE_MIN * 60))

  asegurar_herramientas_ip || { echo "No se pudo asegurar iproute2."; pausa; return; }

  echo "Asignando IP estatica en $IFACE: $START_IP/$PREFIX"
  ip addr flush dev "$IFACE" scope global >/dev/null 2>&1 || true
  ip addr add "$START_IP/$PREFIX" dev "$IFACE" || { echo "ERROR asignando IP."; pausa; return; }
  ip link set "$IFACE" up >/dev/null 2>&1 || true
  guardar_interfaces "$IFACE" "$START_IP" "$MASK"

  mkdir -p /etc/kea /var/lib/kea >/dev/null 2>&1 || true
  if id kea >/dev/null 2>&1; then chown -R kea:kea /var/lib/kea >/dev/null 2>&1 || true; fi

  [ -f "$KEA_CONF" ] && cp "$KEA_CONF" "${KEA_CONF}.bak.$(date +%Y%m%d%H%M%S)" >/dev/null 2>&1 || true

  OPTS=""
  SEP=""
  if [ -n "${GATEWAY:-}" ]; then OPTS="${OPTS}${SEP}{ \"name\": \"routers\", \"data\": \"${GATEWAY}\" }"; SEP=", "; fi
  if [ -n "${DNS_LIST:-}" ]; then DNS_COMMA=$(echo "$DNS_LIST" | tr ' ' ','); OPTS="${OPTS}${SEP}{ \"name\": \"domain-name-servers\", \"data\": \"${DNS_COMMA}\" }"; SEP=", "; fi

  cat > "$KEA_CONF" <<EOF
{
  "Dhcp4": {
    "authoritative": true,
    "interfaces-config": { "interfaces": [ "$IFACE" ] },
    "lease-database": { "type": "memfile", "persist": true, "name": "$KEA_LEASES" },
    "renew-timer": $((LEASE_SEC / 2)),
    "rebind-timer": $((LEASE_SEC * 8 / 10)),
    "valid-lifetime": $LEASE_SEC,
    "subnet4": [
      {
        "id": 1,
        "subnet": "$SUBNET_CIDR",
        "pools": [ { "pool": "$POOL_START_IP - $END_IP" } ],
        "option-data": [ $OPTS ],
        "user-context": { "scope-name": "$SCOPE_NAME" }
      }
    ]
  }
}
EOF

  cat > "$STATE_FILE" <<EOF
SCOPE_NAME="$SCOPE_NAME"
IFACE="$IFACE"
SERVER_IP="$START_IP/$PREFIX"
SUBNET="$SUBNET_CIDR"
POOL="$POOL_START_IP - $END_IP"
GATEWAY="${GATEWAY:-}"
DNS_LIST="${DNS_LIST:-}"
LEASE_MIN="$LEASE_MIN"
EOF

  if existe_comando kea-dhcp4; then
    kea-dhcp4 -t "$KEA_CONF" >/dev/null 2>&1 || { echo "ERROR: Configuracion invalida. Revisa $KEA_CONF"; pausa; return; }
  fi

  rc-update add "$KEA_SVC" default >/dev/null 2>&1 || true
  rc-service "$KEA_SVC" restart || { echo "ERROR reiniciando servicio."; pausa; return; }

  echo "Configuracion aplicada."
  echo "Servidor IP estatica: $START_IP/$PREFIX"
  echo "Pool DHCP: $POOL_START_IP - $END_IP"
  pausa
}

opcion_4_monitoreo() {
  echo "== Monitoreo =="
  if ! esta_instalado; then echo "DHCP no esta instalado."; pausa; return; fi

  echo "-- Status del servicio ($KEA_SVC) --"
  rc-service "$KEA_SVC" status || true

  echo "\n-- Configuracion DHCP ($KEA_CONF) --"
  [ -f "$KEA_CONF" ] && sed -n '1,220p' "$KEA_CONF" || echo "No existe $KEA_CONF"

  echo "\n-- Resumen --"
  if [ -f "$STATE_FILE" ]; then
    . "$STATE_FILE"
    echo "Ambito: ${SCOPE_NAME:-}"
    echo "Interfaz: ${IFACE:-}"
    echo "Servidor IP: ${SERVER_IP:-}"
    echo "Subred: ${SUBNET:-}"
    echo "Pool: ${POOL:-}"
    echo "Gateway: ${GATEWAY:-<omitido>}"
    echo "DNS: ${DNS_LIST:-<omitido>}"
    echo "Lease: ${LEASE_MIN:-} min"
  else
    echo "(Sin estado guardado aun)"
  fi

  echo "\n-- Leases ($KEA_LEASES) --"
  [ -f "$KEA_LEASES" ] && { echo "Ultimas 10 lineas:"; tail -n 10 "$KEA_LEASES"; } || echo "Aun no hay leases."
  pausa
}

opcion_5_reiniciar() {
  echo "== Reiniciar servicio =="
  if ! esta_instalado; then echo "DHCP no esta instalado."; pausa; return; fi
  rc-service "$KEA_SVC" restart && echo "Servicio reiniciado." || echo "Error reiniciando servicio."
  pausa
}

menu() {
  while :; do
    clear 2>/dev/null || true
    echo "--------------------------------------"
    echo "              Menu DHCP               "
    echo "--------------------------------------"
    echo "1) Verificar si DHCP esta instalado"
    echo "2) Instalar DHCP "
    echo "3) Configurar ambito "
    echo "4) Monitoreo "
    echo "5) Reiniciar servicio"
    echo "6) Salir"
    echo "--------------------------------------"
    printf "Elige una opcion: "
    read -r opt
    case "${opt:-}" in
      1) opcion_1_verificar ;;
      2) opcion_2_instalar ;;
      3) opcion_3_configurar ;;
      4) opcion_4_monitoreo ;;
      5) opcion_5_reiniciar ;;
      6) exit 0 ;;
      *) echo "Opcion invalida."; pausa ;;
    esac
  done
}

requiere_root
menu

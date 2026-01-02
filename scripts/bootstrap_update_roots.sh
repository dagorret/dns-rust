#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Uso:
  bootstrap_update_roots.sh [opciones]

Opciones:
  --config PATH           TOML a actualizar (default: config/recursor.toml)
  --out-dir PATH          Dir para root.hints y tmp (default: etc/dnsrust)
  --bootstrap-bin PATH    Binario recursor-bootstrap (default: target/release/recursor-bootstrap)

  --with-dnssec           También genera/actualiza trusted-key.key
  --trust-key PATH        Path de salida para trusted-key.key
                          (default: <out-dir>/trusted-key.key)
  --resolver IP:PUERTO    Resolver para DNSKEY . (repetible)
                          Default si no se indica: 1.1.1.1:53 y 8.8.8.8:53

Ejemplos:
  ./scripts/bootstrap_update_roots.sh
  ./scripts/bootstrap_update_roots.sh --config config/mi.toml
  ./scripts/bootstrap_update_roots.sh --with-dnssec
  ./scripts/bootstrap_update_roots.sh --with-dnssec --resolver 9.9.9.9:53 --resolver 1.1.1.1:53
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CFG_FILE="${ROOT_DIR}/config/recursor.toml"
OUT_DIR="${ROOT_DIR}/etc/dnsrust"
BOOTSTRAP_BIN="${ROOT_DIR}/target/release/recursor-bootstrap"

WITH_DNSSEC=0
TRUST_KEY=""
RESOLVERS=()

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CFG_FILE="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    --bootstrap-bin) BOOTSTRAP_BIN="$2"; shift 2;;

    --with-dnssec) WITH_DNSSEC=1; shift;;
    --trust-key) TRUST_KEY="$2"; shift 2;;
    --resolver) RESOLVERS+=("$2"); shift 2;;

    -h|--help) usage; exit 0;;
    *) echo "ERROR: argumento desconocido: $1" >&2; usage; exit 2;;
  esac
done

# Normalizar rutas relativas al repo si no son absolutas
if [[ "${CFG_FILE}" != /* ]]; then CFG_FILE="${ROOT_DIR}/${CFG_FILE}"; fi
if [[ "${OUT_DIR}" != /* ]]; then OUT_DIR="${ROOT_DIR}/${OUT_DIR}"; fi
if [[ "${BOOTSTRAP_BIN}" != /* ]]; then BOOTSTRAP_BIN="${ROOT_DIR}/${BOOTSTRAP_BIN}"; fi

if [[ -z "${TRUST_KEY}" ]]; then
  TRUST_KEY="${OUT_DIR}/trusted-key.key"
else
  if [[ "${TRUST_KEY}" != /* ]]; then TRUST_KEY="${ROOT_DIR}/${TRUST_KEY}"; fi
fi

if [[ ! -x "${BOOTSTRAP_BIN}" ]]; then
  echo "ERROR: no encuentro el binario ejecutable: ${BOOTSTRAP_BIN}" >&2
  echo "Tip: cargo build --release --bin recursor-bootstrap" >&2
  exit 1
fi

if [[ ! -f "${CFG_FILE}" ]]; then
  echo "ERROR: no existe el config TOML: ${CFG_FILE}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

# 1) Root hints oficiales
"${BOOTSTRAP_BIN}" fetch-roots --out "${OUT_DIR}/root.hints"

# 2) Extraer IPs (archivo temporario de trabajo)
TMP_ROOTS_TOML="${OUT_DIR}/.roots.tmp.toml"
"${BOOTSTRAP_BIN}" extract-root-ips \
  --input "${OUT_DIR}/root.hints" \
  --out-toml "${TMP_ROOTS_TOML}"

ROOTS_LINE="$(grep -E '^roots\s*=' "${TMP_ROOTS_TOML}" | head -n1 || true)"
if [[ -z "${ROOTS_LINE}" ]]; then
  echo "ERROR: no pude obtener roots=... desde ${TMP_ROOTS_TOML}" >&2
  exit 1
fi

# 3) Reemplazar/Agregar roots en el TOML target SIN tocar el resto
python3 - <<PY
import re, pathlib, sys

cfg_path = pathlib.Path(r"${CFG_FILE}")
txt = cfg_path.read_text(encoding="utf-8")

roots_line = r'''${ROOTS_LINE}'''.strip()

block = re.compile(r'(?ms)^roots\\s*=\\s*\\[.*?\\]\\s*$', re.MULTILINE)
line  = re.compile(r'(?m)^roots\\s*=.*$')

if block.search(txt):
    txt2 = block.sub(roots_line, txt, count=1)
elif line.search(txt):
    txt2 = line.sub(roots_line, txt, count=1)
else:
    m = re.search(r'(?m)^upstreams\\s*=.*$', txt)
    if m:
        insert_at = m.end()
        txt2 = txt[:insert_at] + "\\n\\n" + roots_line + "\\n" + txt[insert_at:]
    else:
        m2 = re.search(r'(?m)^\\[', txt)
        if m2:
            insert_at = m2.start()
            txt2 = txt[:insert_at] + roots_line + "\\n\\n" + txt[insert_at:]
        else:
            txt2 = txt + ("\\n" if not txt.endswith("\\n") else "") + roots_line + "\\n"

cfg_path.write_text(txt2 + ("" if txt2.endswith("\\n") else "\\n"), encoding="utf-8")
print("OK: roots actualizados en", cfg_path)
PY

rm -f "${TMP_ROOTS_TOML}"

# 4) DNSSEC trust anchor (opcional)
if [[ "${WITH_DNSSEC}" -eq 1 ]]; then
  if [[ ${#RESOLVERS[@]} -eq 0 ]]; then
    RESOLVERS=("1.1.1.1:53" "8.8.8.8:53")
  fi

  RES_ARGS=()
  for r in "${RESOLVERS[@]}"; do
    RES_ARGS+=(--resolver "$r")
  done

  "${BOOTSTRAP_BIN}" make-trust-anchor --out "${TRUST_KEY}" "${RES_ARGS[@]}"
  echo "OK: trusted-key.key actualizado en ${TRUST_KEY}"
fi

echo "OK: bootstrap completo"
echo " - ${OUT_DIR}/root.hints"
echo " - actualizado: ${CFG_FILE} (roots=...)"
if [[ "${WITH_DNSSEC}" -eq 1 ]]; then
  echo " - ${TRUST_KEY}"
fi

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BOOTSTRAP_BIN="${ROOT_DIR}/target/release/recursor-bootstrap"
OUT_DIR="${ROOT_DIR}/etc/dnsrust"
CFG_FILE="${ROOT_DIR}/config/recursor.toml"

mkdir -p "${OUT_DIR}"

# 1) Actualizar root hints
"${BOOTSTRAP_BIN}" fetch-roots --out "${OUT_DIR}/root.hints"

# 2) Generar roots.auto.toml (roots = [...])
"${BOOTSTRAP_BIN}" extract-root-ips \
  --input "${OUT_DIR}/root.hints" \
  --out-toml "${OUT_DIR}/roots.auto.toml"

# 3) Generar trust anchor DNSSEC
"${BOOTSTRAP_BIN}" make-trust-anchor \
  --out "${OUT_DIR}/trusted-key.key" \
  --resolver 1.1.1.1:53 \
  --resolver 8.8.8.8:53

# 4) Inyectar roots en config/recursor.toml (sin tocar el resto)
ROOTS_LINE="$(grep -E '^roots\s*=' "${OUT_DIR}/roots.auto.toml" | head -n1)"
if [[ -z "${ROOTS_LINE}" ]]; then
  echo "ERROR: no pude leer roots=... desde ${OUT_DIR}/roots.auto.toml" >&2
  exit 1
fi

python3 - <<PY
import re, pathlib, sys
cfg_path = pathlib.Path(r"${CFG_FILE}")
txt = cfg_path.read_text(encoding="utf-8")

roots_line = r'''${ROOTS_LINE}'''.strip()

# Reemplaza bloque multi-línea:
# roots = [
#   ...
# ]
pattern_block = re.compile(r'(?ms)^roots\\s*=\\s*\\[.*?\\]\\s*$', re.MULTILINE)

# Reemplaza línea single-line:
pattern_line = re.compile(r'(?m)^roots\\s*=.*$')

if pattern_block.search(txt):
    txt2 = pattern_block.sub(roots_line, txt, count=1)
elif pattern_line.search(txt):
    txt2 = pattern_line.sub(roots_line, txt, count=1)
else:
    print("ERROR: no encontré 'roots = ...' en el config para reemplazar", file=sys.stderr)
    sys.exit(2)

cfg_path.write_text(txt2 + ("" if txt2.endswith("\n") else "\n"), encoding="utf-8")
print("OK: roots actualizados en", cfg_path)
PY

echo "OK: bootstrap completo"
echo " - ${OUT_DIR}/root.hints"
echo " - ${OUT_DIR}/roots.auto.toml"
echo " - ${OUT_DIR}/trusted-key.key"
echo " - actualizado: ${CFG_FILE}"

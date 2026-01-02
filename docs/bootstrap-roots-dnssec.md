# Bootstrap de Roots y DNSSEC (rust-dns-recursor)

Este documento describe **qué se implementó** y **cómo se obtienen / actualizan**
automáticamente:

- Root hints (servidores raíz DNS)
- Trust Anchor DNSSEC (`DNSKEY .`)

Todo el proceso es **no interactivo**, **idempotente** y reproducible.

---

## 1. Objetivo

Evitar:

- Roots hardcodeados a mano
- Actualizaciones manuales
- Dependencia de archivos externos no versionados

Y garantizar que el recursor:

- Use **root servers oficiales de IANA**
- Tenga disponible la **clave raíz DNSSEC actual**
- Pueda automatizar el proceso (cron / CI / systemd)

---

## 2. Componentes implementados

### 2.1 Binario: `recursor-bootstrap`

Binario independiente dentro del workspace Cargo:



src/bin/recursor-bootstrap.rs

`Se compila con: ```bash cargo build --release --bin recursor-bootstrap`

### Comandos disponibles

`recursor-bootstrap fetch-roots recursor-bootstrap extract-root-ips recursor-bootstrap make-trust-anchor`

---

## 3. Obtención de Root Servers (IANA)

### 3.1 Fuente oficial

Los root hints se obtienen desde **IANA / InterNIC**:

`https://www.internic.net/domain/named.root`

Este archivo contiene:

- Nombres de root servers (`a.root-servers.net`, etc.)

- Registros `A` y `AAAA` oficiales

---

### 3.2 Descargar root hints

`./target/release/recursor-bootstrap fetch-roots \   --out etc/dnsrust/root.hints`

Resultado:

`etc/dnsrust/root.hints`

Este archivo **no se edita** a mano.

---

### 3.3 Extraer IPs para el recursor

Como el recursor usa:

`roots = ["IP", ...]`

se extraen automáticamente los registros `A` y `AAAA`:

`./target/release/recursor-bootstrap extract-root-ips \   --input etc/dnsrust/root.hints \   --out-toml etc/dnsrust/roots.auto.toml`

Ejemplo generado:

`roots = [  "198.41.0.4",  "199.9.14.201",  "192.33.4.12",  "2001:503:ba3e::2:30",   ... ]`

---

## 4. Actualización automática del `recursor.toml`

### 4.1 Script unificado

Script:

`scripts/bootstrap_update_roots.sh`

Responsabilidades:

1. Descargar `root.hints`

2. Extraer IPs

3. **Actualizar o insertar** el bloque `roots = [...]`  
   dentro del TOML real del recursor

4. (Opcional) generar DNSSEC trust anchor

No toca:

- cache

- filters

- zones

- otros parámetros

---

### 4.2 Uso básico

Actualizar solo roots:

`./scripts/bootstrap_update_roots.sh`

Actualizar roots en otro TOML:

`./scripts/bootstrap_update_roots.sh --config config/mi.toml`

---

## 5. Obtención de DNSSEC Trust Anchor

### 5.1 Qué se genera

Se genera el archivo:

`trusted-key.key`

Formato requerido por **Hickory Recursor**:

`. <TTL> IN DNSKEY <flags> <protocol> <algorithm> <public_key>`

Ejemplo:

`. 172800 IN DNSKEY 257 3 8 AwEAAb... . 172800 IN DNSKEY 256 3 8 AwEAAd...`

---

### 5.2 Cómo se obtiene la clave

El binario:

- Consulta `DNSKEY .`

- Usa resolvers configurables

- Intenta UDP → si hay truncation → **fallback a TCP**

- Compatible con redes donde UDP no alcanza

---

### 5.3 Generar trust anchor manualmente

`./target/release/recursor-bootstrap make-trust-anchor \   --out etc/dnsrust/trusted-key.key \   --resolver 1.1.1.1:53 \   --resolver 8.8.8.8:53`

---

### 5.4 Generar trust anchor junto con roots

`./scripts/bootstrap_update_roots.sh --with-dnssec`

Resultado:

`etc/dnsrust/ ├── root.hints ├── trusted-key.key`

---

## 6. Flujo completo (automático)

`IANA  └─ named.root       ↓ fetch-roots       ↓ root.hints       ↓ extract-root-ips       ↓ roots = [...]       ↓ bootstrap_update_roots.sh       ↓ config/recursor.toml (roots actualizados)`

Y opcionalmente:

`DNSKEY .   ↓ make-trust-anchor   ↓ trusted-key.key`

---

## 7. Estado actual del recursor

En `config/recursor.toml`:

`[recursor] dnssec = "off"`

Por lo tanto:

- ✔ roots actualizados automáticamente

- ✔ trust anchor generado

- ❌ DNSSEC todavía no activo en runtime
# Bootstrap de Roots y DNSSEC (rust-dns-recursor)

Este documento describe **qué se implementó** y **cómo se obtienen / actualizan**
automáticamente:

- Root hints (servidores raíz DNS)
- Trust Anchor DNSSEC (`DNSKEY .`)

Todo el proceso es **no interactivo**, **idempotente** y reproducible.

## Objetivo

Evitar roots hardcodeados a mano y actualizaciones manuales, garantizando:

- Roots oficiales desde IANA/InterNIC (`named.root`)
- Trust anchor DNSSEC disponible (`DNSKEY .`)
- Automatización (CI/cron/systemd)

## Binario: `recursor-bootstrap`

Ubicación:

- `src/bin/recursor-bootstrap.rs`

Build:

```bash
cargo build --release --bin recursor-bootstrap

Comandos:

`./target/release/recursor-bootstrap fetch-roots \   --out etc/dnsrust/root.hints`

Extraer IPs:

`./target/release/recursor-bootstrap extract-root-ips \   --input etc/dnsrust/root.hints \   --out-toml etc/dnsrust/roots.auto.toml`

## Actualización automática del TOML real del recursor

Script:

- `scripts/bootstrap_update_roots.sh`

Actualiza/inserta **solo** el bloque `roots = [...]` dentro de:

- `config/recursor.toml` (por defecto)

- o cualquier otro con `--config`

Ejemplos:

`./scripts/bootstrap_update_roots.sh ./scripts/bootstrap_update_roots.sh --config config/mi.toml`

## DNSSEC trust anchor

Genera `trusted-key.key` consultando `DNSKEY .`.

Manual:

`./target/release/recursor-bootstrap make-trust-anchor \   --out etc/dnsrust/trusted-key.key \   --resolver 1.1.1.1:53 \   --resolver 8.8.8.8:53`

Integrado:

`./scripts/bootstrap_update_roots.sh --with-dnssec`

## Estado actual

En `config/recursor.toml`:

`[recursor] dnssec = "off"`

Entonces:

- ✅ roots actualizados automáticamente

- ✅ trust anchor generado


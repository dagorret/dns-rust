# rust-dns-recursor (proyecto completo)

Servidor DNS **recursivo/iterativo** (no forwarder) escrito en Rust usando la familia Hickory DNS, con:

1) Iterativo sin DNSSEC (por defecto), solo **A/AAAA** (igual podés reenviar otros tipos con `--allow-other-types`).  
   Root hints **fijos** (configurables en `config/example.toml`).

2) Cache de **NS + glue**, retry/timeout y **TCP fallback** (esto lo aporta el motor `hickory-recursor`, que implementa el algoritmo de RFC 1034/1035 y expone parámetros de cache/recursion).  
   Además hay un **cache frontal** de respuestas (positivo y negativo) para acelerar mucho el server bajo carga.

3) **Negative caching** y **CNAME chain**:
   - CNAME chains: el recursor las sigue y devuelve la respuesta final (y se cachea).
   - Negative caching: cache de NXDOMAIN/NOERROR vacío (con TTL configurable) *en el cache frontal*.

4) (Opcional) **DNSSEC**:
   - Compila con: `cargo run --features dnssec -- -c config/example.toml`
   - Usa `DnssecPolicy::ValidateWithStaticKey { trust_anchor: None }` (trust anchor built-in) si lo habilitás en el config.

Además:
- **Filtros**: allowlist/blocklist por dominio + allow/deny por redes IP destino (para no consultar RFC1918/loopback, etc.)
- **Zonas** “locales”: overrides de A/AAAA/CNAME/TXT/MX/NS por archivos TOML (`zones/*.toml`).
- UDP + TCP listener.

> Nota: “hacer un Unbound” entero es un laburo enorme; este proyecto está pensado como una base muy sólida para seguir creciendo.

---

## Ejecutar

```bash
# en modo recursivo sin DNSSEC (default):
cargo run -- -c config/example.toml

# con DNSSEC (si querés validación):
cargo run --features dnssec -- -c config/example.toml
```

Por defecto escucha en `0.0.0.0:5353` (no 53 para evitar permisos). Probá:

```bash
dig @127.0.0.1 -p 5353 www.unrc.edu.ar A
dig @127.0.0.1 -p 5353 www.cloudflare.com AAAA
```

---

## Configuración

Mirá `config/example.toml`.

- `roots`: IPs de root servers (hints).
- `zones_dir`: carpeta con zonas locales.
- `filters`: allowlist/blocklist y redes deny/allow.
- `cache`: tamaños y TTLs.

---

## Estructura

- `src/main.rs`: arranque, config, logs, listeners
- `src/handler.rs`: RequestHandler, cache frontal, filtros, zonas, recursor
- `src/recursor_engine.rs`: wrapper del `hickory_recursor::Recursor`
- `src/cache.rs`: cache positivo/negativo (moka)
- `src/filters.rs`: domain allow/block + ip allow/deny
- `src/zones.rs`: zona local (TOML -> RRsets)

---

## Referencias
- Hickory recursor (iterative algorithm basado en RFC 1034): docs del `Recursor::resolve`.
- Configuración de root hints (IANA).

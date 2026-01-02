# Cache: modos y configuración

Este proyecto soporta dos modos de dimensionamiento del cache:

- **Modo A (por entradas)**: simple, default, compatible con configs existentes.
- **Modo B (por memoria / bytes)**: recomendado para producción, evita crecimiento no controlado del RSS.

---

## Modo A: por entradas (default)

Se usa cuando **NO** se configuran `answer_cache_max_bytes` / `negative_cache_max_bytes`.

```toml
[cache]
answer_cache_size = 200000
negative_cache_size = 80000
```

Características:
- Capacidad por “cantidad de claves” (entradas).
- Fácil de entender, pero el uso real de memoria depende del tamaño promedio de respuestas.

---

## Modo B: por memoria (weighted)

Se activa cuando se configura al menos uno de los campos `*_max_bytes`:

```toml
[cache]
answer_cache_max_bytes = 512000000
negative_cache_max_bytes = 128000000
```

Características:
- Limita el cache por una aproximación de bytes.
- Internamente usa un **weigher** que estima el peso de cada entrada:

```
peso ≈ entry.bytes.len() + key.qname_lc.len() + 64
```

> Nota: es una aproximación (hay overhead extra del runtime/alloc/hashing), pero es suficiente para control operativo del RSS.

---

## Prefetch y Stale-While-Revalidate (SWR)

Independiente del modo A/B, aplica al cache positivo:

- `prefetch_threshold_secs`: si a una entrada le queda poco TTL, se sirve desde cache y se revalida en background.
- `stale_window_secs`: si ya expiró pero está dentro de esta ventana, se puede servir stale y revalidar en background.

---

## Cache negativo

El bloque `[cache.negative]` controla NXDOMAIN/NODATA y la política `two_hit`.

---

## Ejemplo completo (Modo B, producción)

```toml
[cache]
answer_cache_size = 20000          # requerido por compatibilidad (se ignora si hay max_bytes)
negative_cache_size = 20000        # requerido por compatibilidad (se ignora si hay max_bytes)

answer_cache_max_bytes = 512000000
negative_cache_max_bytes = 128000000

min_ttl = 10
max_ttl = 3600
negative_ttl = 300

prefetch_threshold_secs = 30
stale_window_secs = 120

[cache.negative]
enabled = true
cache_nxdomain = true
cache_nodata = true
two_hit = true
probe_ttl_secs = 60
min_ttl = 30
max_ttl = 600
```

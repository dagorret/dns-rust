# Opciones de Cache (`opciones_cache.md`)

Este documento enumera **todas las opciones de cache** disponibles en el proyecto *rust-dns-recursor* (según el estado actual de `CacheConfig` / `NegativeCacheConfig` y la implementación de handler/cache que venimos integrando).

> Nota: Estas opciones aplican tanto en modo **FORWARDER** como en modo **RECURSOR ITERATIVO**. El modo sólo cambia **de dónde** se obtienen las respuestas; el cache actúa igual.

---

## 1) Configuración principal: `[cache]`

### `answer_cache_size` *(u64)*

Capacidad del cache **positivo** (respuestas con ANSWER).

- **Efecto**: máximo de entradas que se guardan en `answers`.
- **Tipo**: tamaño lógico (cantidad), no bytes.

Ejemplo:

```toml
[cache]
answer_cache_size = 20000
```

---

### `negative_cache_size` *(u64)*

Capacidad del cache **negativo** (NXDOMAIN / NODATA) y su probe-cache (two-hit).

Ejemplo:

```toml
[cache]
negative_cache_size = 20000
```

---

### `min_ttl` *(u64, segundos)*

Límite inferior para TTL **positivo** (clamp).

- **Efecto**: evita TTL demasiado bajo que genere exceso de consultas.
- Se aplica al TTL efectivo almacenado en cache positivo.

Ejemplo:

```toml
[cache]
min_ttl = 5
```

---

### `max_ttl` *(u64, segundos)*

Límite superior para TTL **positivo** (clamp).

- **Efecto**: evita cachear “para siempre” si un upstream devuelve TTL excesivo.

Ejemplo:

```toml
[cache]
max_ttl = 300
```

---

### `negative_ttl` *(u64, segundos)*

TTL fallback para cache **negativo**, cuando no se infiere TTL desde SOA (RFC 2308).

- **Efecto**: cuánto dura una entrada negativa *si no hay SOA/minimum*.
- En la implementación actual se usa como base y luego se **clamp** con `cache.negative.min_ttl/max_ttl`.

Ejemplo:

```toml
[cache]
negative_ttl = 60
```

---

### `prefetch_threshold_secs` *(u64, segundos)*

Umbral de **Prefetch** para cache positivo.

- Si una entrada está **vigente**, pero le queda `<= prefetch_threshold_secs` para expirar, se considera `NearExpiry`.
- **Comportamiento**:
  - se responde desde cache inmediatamente
  - y se dispara una **revalidación en background** (refresh).

Ejemplo:

```toml
[cache]
prefetch_threshold_secs = 10
```

**Recomendación inicial**: 5–30s (según latencia de upstream y carga).

---

### `stale_window_secs` *(u64, segundos)*

Ventana de **Stale-While-Revalidate (SWR)** para cache positivo.

- Si una entrada ya expiró pero aún está dentro de `stale_window_secs`, se considera `Stale`.
- **Comportamiento**:
  - se sirve la respuesta stale (mejor latencia / disponibilidad)
  - y se revalida en background.

Ejemplo:

```toml
[cache]
stale_window_secs = 30
```

**Recomendación inicial**: 10–120s (según tolerancia a “stale”).

---

## 2) Cache negativo: `[cache.negative]`

> El cache negativo se aplica a respuestas:
> 
> - `NXDOMAIN` (dominio inexistente)
> - `NODATA` (NOERROR pero sin answers para ese qtype)
> 
> Con políticas para reducir ruido (two-hit).

### `enabled` *(bool)*

Habilita/deshabilita cache negativo en general.

Ejemplo:

```toml
[cache.negative]
enabled = true
```

---

### `cache_nxdomain` *(bool)*

Si `true`, cachea respuestas `NXDOMAIN`.

Ejemplo:

```toml
[cache.negative]
cache_nxdomain = true
```

---

### `cache_nodata` *(bool)*

Si `true`, cachea `NODATA` (NOERROR sin answers).

Ejemplo:

```toml
[cache.negative]
cache_nodata = true
```

> Nota: si hoy no ves efecto, es porque puede faltar usar esta opción explícitamente en el handler para el caso NODATA (dependiendo de tu versión exacta).

---

### `two_hit` *(bool)*

Política anti-ruido “2-hit”.

- **Idea**: muchos NXDOMAIN son typos/DGA/ruido. No queremos cachearlos inmediatamente.
- **Comportamiento**:
  - 1er hit: no cachea; sólo registra un probe (corto)
  - 2do hit (dentro del probe_ttl): recién cachea negativo real

Ejemplo:

```toml
[cache.negative]
two_hit = true
```

---

### `probe_ttl_secs` *(u64, segundos)*

TTL de la marca “probe” usada en `two_hit`.

- Si el 2do hit no llega dentro de este TTL, se pierde el “primer hit” y vuelve a empezar.

Ejemplo:

```toml
[cache.negative]
probe_ttl_secs = 60
```

---

### `min_ttl` *(u64, segundos)*

Clamp mínimo del TTL negativo (para evitar TTL demasiado bajo).

Ejemplo:

```toml
[cache.negative]
min_ttl = 5
```

---

### `max_ttl` *(u64, segundos)*

Clamp máximo del TTL negativo (para evitar caches negativos eternos).

Ejemplo:

```toml
[cache.negative]
max_ttl = 300
```

---

## 3) Ejemplo completo recomendado (base)

```toml
[cache]
answer_cache_size = 20000
negative_cache_size = 20000

min_ttl = 5
max_ttl = 300
negative_ttl = 60

prefetch_threshold_secs = 10
stale_window_secs = 30

[cache.negative]
enabled = true
cache_nxdomain = true
cache_nodata = true
two_hit = true
probe_ttl_secs = 60
min_ttl = 5
max_ttl = 300
```

---

## 4) Notas operativas

- **Prefetch y SWR** se aplican al cache **positivo** (`answers`).
- El cache negativo usa `two_hit` para reducir ruido.
- Los flags DNS (RA/AD/AA) deben ser consistentes:
  - `RA=1` cuando el servidor ofrece recursión
  - `AD=0` si no hay validación DNSSEC
  - `AA=0` en respuestas no autoritativas

---

## 5) Checklist rápido

- ¿Querés máxima frescura y baja latencia? → subir `prefetch_threshold_secs` (con moderación).
- ¿Querés tolerancia a upstream lento? → subir `stale_window_secs`.
- ¿Mucho ruido NXDOMAIN? → `two_hit=true` y `probe_ttl_secs` razonable.
- ¿No querés cache negativo? → `cache.negative.enabled=false`.

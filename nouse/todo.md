# Roadmap de desarrollo – Resolver DNS orientado a ISP

Este documento describe **el estado actual** de mi servidor DNS y **las decisiones de diseño y desarrollo inmediato** necesarias para que escale correctamente a un entorno **ISP** antes de incorporar DNSSEC.

El foco está en **robustez, performance, cache y operación**, no en features criptográficas todavía.

---

## 0️⃣ Estado actual del proyecto (baseline)

Hoy tengo un **servidor DNS funcional y serio**, con las siguientes capacidades:

- Soporte **UDP y TCP**
- Modo **Forwarder (upstream)** y **Recursor iterativo completo**
- Cache positiva y negativa
- TTL mínimo y máximo configurables
- Blocklist de dominios
- Filtros por red IP
- Zonas locales
- Transporte IPv4-only (controlado)
- Tests de integración reales usando `dig`
- Tests de cache (positiva y negativa)
- Tests de recursión iterativa reales (marcados como `#[ignore]`)

Esto ya es suficiente para **LAN, homelab serio, entornos internos y edge DNS**.

---

## 1️⃣ ¿Estamos construyendo un servidor DNS robusto?

**Sí. Claramente sí.**

No es un proyecto experimental ni un toy:

- Resuelve por wire (UDP/TCP)
- Tiene cache real (positiva y negativa)
- Puede operar como forwarder o como recursor completo
- Tiene tests de integración reales
- Está escrito en Rust (seguridad, control de memoria, performance)

La base es **sólida y extensible**.

---

## 2️⃣ ¿Para qué tamaño de consultas está pensado?

### Escala esperada hoy

- **Modo Forwarder**
  - Miles a decenas de miles de QPS
  - Ideal para edge, PoP, redes corporativas
  - Escala principalmente con cache

- **Modo Recursor iterativo**
  - Menor QPS que forwarder
  - Optimizado para redes medianas
  - Adecuado para ISP pequeño / regional / privacidad

### No es (todavía):

- Un resolver global tipo 8.8.8.8
- Un servicio de millones de QPS a escala planetaria

👉 **Eso es intencional**. El objetivo es ISP, no hyperscale global.

---

## 3️⃣ ¿Es Full Recursivo?

**Sí.**

En modo recursor:

- Arranco desde root servers
- Sigo delegaciones
- Llego a servidores autoritativos
- Cacheo NS, respuestas y NXDOMAIN

Es un **resolver iterativo real**, no un forwarder disfrazado.

---

## 4️⃣ ¿Tiene upstream?

**Sí, y es clave.**

- En modo forwarder uso uno o varios upstreams
- Puedo hacer fallback y balanceo
- Ideal para redes restringidas o edge

El diseño es **mutuamente excluyente**:
- Si hay `upstreams` → soy forwarder
- Si no hay `upstreams` → soy recursor

Esto simplifica la lógica y evita ambigüedades.

---

## 5️⃣ ¿Qué tipo de cache tengo hoy?

### Cache actual

- Cache positiva (A, AAAA, MX, TXT, etc.)
- Cache negativa (NXDOMAIN)
- TTL mínimo y máximo configurables
- TTL negativo configurable

### Qué **todavía no tengo**
- Prefetch
- Serve-stale
- Single-flight por key
- Cache diferenciada por política

👉 **La base está**, pero para ISP necesito ir más allá.

---

# 🧭 Decisión clave: arquitectura ISP

## Prioridad 0️⃣ – Arquitectura en dos capas

Para ISP, **no uso un solo tipo de instancia**.

### Arquitectura recomendada

**Capa Edge (por PoP / ciudad)**
- Modo: Forwarder
- Upstreams: resolvers core
- Absorbe QPS
- Latencia mínima al cliente

**Capa Core**
- Modo: Recursor iterativo
- Cache caliente
- 2–6 instancias
- Menos QPS, más trabajo por query

Mi software **puede cumplir ambos roles** solo cambiando config.

---

# 🚀 Desarrollo inmediato (antes de DNSSEC)

## Prioridad 1️⃣ – Cache “de ISP” (lo más importante)

La cache **es la escala real**.

### 1) Prefetch (warm cache)
- Si un registro es popular y está por expirar:
  - Lo revalido antes
- Reduce p95/p99
- Evita avalanchas cuando expira TTL

### 2) Serve-stale (stale-while-revalidate)
- Si un upstream / autoritativo está lento o caído:
  - Sirvo respuesta expirada por 30–300s
  - Revalido en background

Esto es lo que evita caídas visibles cuando Internet se degrada.

### 3) Cache negativa correcta
- Respetar TTL negativo del SOA cuando existe
- Usar `negative_ttl` solo como fallback

### 4) Cache por política
- Diferenciar RRTypes
- Dominios “ruidosos” con reglas propias

Con esto paso de “resolver robusto” a **resolver de operador**.

---

## Prioridad 2️⃣ – Control de concurrencia (stampede control)

Problema típico ISP:
> 1000 clientes preguntan lo mismo al expirar TTL

Solución:
- **Single-flight por key**
- Una sola recursión en vuelo
- Los demás esperan esa respuesta

Esto reduce brutalmente la carga en picos.

---

## Prioridad 3️⃣ – Transporte y performance

### Ya tengo:
- UDP rápido
- TCP funcional

### Falta reforzar:
- EDNS0 buffer size (1232 bytes recomendado)
- Caer a TCP solo cuando corresponde
- Ajustes de runtime:
  - workers
  - UDP recv buffer
  - límites por request costoso

---

## Prioridad 4️⃣ – Resiliencia operativa

### Multi-upstream real
- Health-check
- Backoff
- Jitter
- Retry controlado

### Circuit breakers
- Si un root/TLD/autoritativo falla
- No insistir miles de veces por segundo

---

## Prioridad 5️⃣ – Seguridad ISP (antes de DNSSEC)

Antes que DNSSEC, necesito:

1) Anti-amplificación
   - No responder ANY
   - Limitar respuestas grandes
   - Rate-limit básico

2) RRL (Response Rate Limiting)

3) QNAME minimization
   - Mejora privacidad
   - Reduce superficie de ataque

---

## Prioridad 6️⃣ – Observabilidad (obligatoria)

Sin métricas **no se opera un ISP**.

Métricas mínimas:
- QPS total / por tipo
- Cache hit rate (positiva y negativa)
- Latencia p50 / p95 / p99
- Timeouts upstream
- SERVFAIL
- Top dominios
- Top NXDOMAIN
- In-flight concurrentes

Logs con sampling, no todo.

---

# 🧩 Ajustes inmediatos a nivel DNS protocol

Para quedar **LAN / ISP-ready** a corto plazo:

- Marcar `RA = 1` si soy recursor
- Glue básico para MX y NS
- Flags correctos (RA / AA / AD)
- NXDOMAIN y SOA bien formados

---

## 🧭 Conclusión

Hoy estoy construyendo un **resolver DNS serio**, no experimental.

Antes de DNSSEC, mi foco es:
- Cache avanzada
- Concurrencia controlada
- Resiliencia
- Observabilidad
- Arquitectura edge/core

Cuando eso esté sólido, **DNSSEC entra sin romper nada**.

Este es el camino correcto para un **resolver DNS de ISP**.


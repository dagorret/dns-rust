# Cache DNS: Prefetch y Stale-While-Revalidate

Este documento describe las políticas de cache implementadas en
**rust-dns-recursor**, alineadas con buenas prácticas operativas y
resolvers modernos.

---

## 1. Objetivos del cache

- Reducir latencia percibida
- Evitar picos de carga (“cache stampede”)
- Mejorar disponibilidad ante upstream lentos
- Mantener semántica DNS correcta

---

## 2. Prefetch

### Descripción

El prefetch consiste en actualizar una entrada **antes** de que expire,
cuando su TTL restante cae por debajo de un umbral configurable.

### Comportamiento

- La respuesta se sirve desde cache
- La actualización ocurre en background
- El cliente no espera

### Configuración

```toml
[cache]
prefetch_threshold_secs = 10


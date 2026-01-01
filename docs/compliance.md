# DNS Compliance y Buenas Prácticas

Este documento describe cómo el proyecto **rust-dns-recursor** se ajusta a las normas técnicas vigentes, a las buenas prácticas operativas y al uso y costumbre en implementaciones de servidores DNS recursivos modernos.

---

## 1. Alcance

Este documento cubre:

- Comportamiento de flags DNS (RA, AA, AD, RD)
- Operación como recursor y forwarder
- Respuestas NXDOMAIN y cache negativo
- Interoperabilidad con clientes DNS estándar

Quedan explícitamente fuera de alcance:

- Operación como servidor autoritativo
- Validación DNSSEC completa

---

## 2. Flags DNS

### 2.1 RA – Recursion Available

- El servidor marca `RA = 1` en todas las respuestas cuando opera como recursor.
- El valor de `RA` es independiente del flag `RD` solicitado por el cliente.

Justificación:

- Cumple RFC 1035.
- Evita advertencias en clientes estándar (`dig`).
- Refleja correctamente la capacidad real del servidor.

---

### 2.2 AA – Authoritative Answer

- El flag `AA` nunca se marca.

Justificación:

- El servidor no mantiene zonas autoritativas.
- Evita inducir a error a caches intermedios y clientes.

---

### 2.3 AD – Authenticated Data

- El flag `AD` siempre se establece en `0`.

Justificación:

- El servidor no realiza validación DNSSEC.
- Se evita afirmar propiedades criptográficas no garantizadas.

---

## 3. NXDOMAIN y Cache Negativo

- Las respuestas NXDOMAIN se devuelven con `RCODE = NXDOMAIN`.
- El servidor implementa cache negativo para reducir consultas recursivas repetidas.
- El comportamiento es compatible con la práctica común de resolvers recursivos.

Nota:

- El diseño prioriza estabilidad y previsibilidad por sobre micro-optimizaciones.

---

## 4. Interoperabilidad

- Compatible con herramientas estándar como `dig`.
- Compatible con resolvers del sistema (`resolv.conf`).
- No genera advertencias espurias en clientes comunes.

---

## 5. Estado de Cumplimiento

| Área           | Estado                      |
| -------------- | --------------------------- |
| Flags DNS      | Cumple                      |
| Recursión      | Cumple                      |
| NXDOMAIN       | Cumple                      |
| Cache negativo | Cumple                      |
| DNSSEC         | No implementado (explícito) |

---

## Decisiones de diseño y trade-offs

Esta sección documenta explícitamente las decisiones de diseño adoptadas, junto con los compromisos (trade-offs) asumidos.

### Resolver recursivo no autoritativo

**Decisión:** el servidor opera exclusivamente como recursor / forwarder.

**Trade-off:**

- Ventaja: simplicidad del modelo, menor superficie de error, interoperabilidad clara.
- Desventaja: no puede utilizarse como servidor autoritativo sin cambios estructurales.

---

### Publicidad explícita de capacidades (`RA = 1`)

**Decisión:** se marca siempre `RA = 1` cuando el servidor ofrece recursión.

**Trade-off:**

- Ventaja: comportamiento explícito y compatible con clientes estándar.
- Desventaja: el servidor anuncia recursión incluso ante consultas que no la requieran.

---

### No afirmación de autoridad (`AA = 0`)

**Decisión:** el flag `AA` nunca se marca.

**Trade-off:**

- Ventaja: evita ambigüedad semántica en caches intermedios.
- Desventaja: no se aprovechan posibles optimizaciones autoritativas.

---

### DNSSEC no validante (`AD = 0`)

**Decisión:** no se implementa validación DNSSEC y el flag `AD` se mantiene en `0`.

**Trade-off:**

- Ventaja: implementación más simple y predecible.
- Desventaja: no se ofrecen garantías criptográficas sobre los datos.

---

### Cache negativo conservador

**Decisión:** el cache negativo se implementa de forma conservadora y compatible con RFC 2308.

**Trade-off:**

- Ventaja: estabilidad y reducción de consultas repetidas.
- Desventaja: posibles consultas adicionales en escenarios límite.

---

### Prioridad a interoperabilidad sobre micro-optimización

**Decisión:** se prioriza un comportamiento claro y compatible por sobre optimizaciones agresivas dependientes del entorno.

**Trade-off:**

- Ventaja: resultados deterministas y previsibles.
- Desventaja: rendimiento marginalmente inferior en escenarios muy específicos.

## 6. Conclusión

El proyecto **rust-dns-recursor** presenta un comportamiento conforme a las normas técnicas aplicables, a las buenas prácticas operativas y al uso y costumbre de servidores DNS recursivos modernos, manteniendo un diseño explícito y conservador respecto a sus capacidades.





## Ejecución y verificación

Esta sección describe los comandos recomendados para ejecutar el servicio y validar el comportamiento esperado.

### Selección explícita de configuración

Se recomienda ejecutar el binario indicando el archivo de configuración:

- Forwarder (usa `upstreams`):
  - `cargo run -- -c config/up.toml`
- Recursor iterativo (usa `roots`, requiere conectividad a Internet):
  - `cargo run -- -c config/rec.toml`

Nota: el modo operativo se determina por el contenido del archivo de configuración (presencia de `upstreams` y/o `roots`).

### Puertos de escucha en entornos de desarrollo

- Evitar `5353` (habitualmente utilizado por mDNS/Avahi).
- Preferir puertos no privilegiados (por ejemplo `1053` o un puerto alto) y, cuando se requiere uso local, limitar a `127.0.0.1`.

### Pruebas manuales con `dig`

Con el servicio en ejecución, se recomienda verificar:

- Respuesta con `RA = 1` y sin `AD` (si no se valida DNSSEC):
  
  - `dig @127.0.0.1 -p <PUERTO> example.com A +noall +comments +answer`

- Consultas adicionales:
  
  - `dig @127.0.0.1 -p <PUERTO> example.com AAAA`
  - `dig @127.0.0.1 -p <PUERTO> nonexistent-domain-example.invalid A`

### Suite de tests

- Tests normales:
  
  - `cargo test`

- Tests de integración DNS:
  
  - `cargo test --test dns_integration -- --nocapture`

- Tests de recursor iterativo (requiere Internet):
  
  - `cargo test --test dns_integration -- --nocapture --ignored`

### Operación segura durante desarrollo

- Si el proceso quedó escuchando (puerto ocupado), finalizar la instancia antes de reiniciar:
  - `pkill rust-dns-recursor`
  - o identificar PID y ejecutar `kill <PID>`.

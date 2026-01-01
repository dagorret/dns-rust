# Referencias Normativas y Técnicas

Este documento lista las normas, RFCs y referencias técnicas relevantes para el diseño y la implementación del proyecto **rust-dns-recursor**.

---

## 1. RFCs Fundamentales

### RFC 1035 – Domain Names: Implementation and Specification

- Define el formato de mensajes DNS.
- Establece el significado de los flags `QR`, `RD`, `RA`, `AA`.
- Base normativa para resolvers y servidores autoritativos.

---

### RFC 2308 – Negative Caching of DNS Queries

- Define el comportamiento de NXDOMAIN.
- Establece el uso de SOA y TTLs para cache negativo.
- Base normativa para evitar consultas repetidas a dominios inexistentes.

---

## 2. DNSSEC (Referencia parcial)

### RFC 4035 – DNSSEC Protocol

- Define los flags `AD` y `CD`.
- Establece el significado de “datos autenticados”.

Nota:
- **rust-dns-recursor no implementa validación DNSSEC** y, por lo tanto, no afirma autenticidad de datos.

---

### RFC 6840 – Clarifications and Implementation Notes for DNSSEC

- Aclara el uso correcto de los flags relacionados con DNSSEC.
- Refuerza la necesidad de no marcar `AD` sin validación efectiva.

---

## 3. Uso y Costumbre (Implementaciones de Referencia)

El comportamiento del proyecto se alinea con resolvers ampliamente desplegados:

- **Unbound**
- **BIND (modo recursor)**
- **PowerDNS Recursor**

En particular:
- `RA = 1` cuando el servidor ofrece recursión.
- `AA = 0` en respuestas no autoritativas.
- `AD = 0` cuando no se valida DNSSEC.

---

## 4. Documentación Complementaria

- `man dig`
- Documentación de Unbound y PowerDNS
- Pruebas de interoperabilidad con clientes estándar

---

## 5. Nota Final

Las referencias listadas en este documento constituyen la base normativa y técnica utilizada para justificar las decisiones de diseño adoptadas en **rust-dns-recursor**.


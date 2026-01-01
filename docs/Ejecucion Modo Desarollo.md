---

# 📄 Ejecucion-modo-desarrollo.md`

```md
# Ejecución en modo desarrollo

Este documento describe cómo ejecutar el servidor DNS en modo desarrollo.

---

## ▶️ Ejecutar con Cargo

### Forwarder (modo upstream)

```bash
cargo run -- --config config/up.toml
```

### Recursor iterativo

`cargo run -- --config config/recursor.toml`

---

## 🔍 Probar con dig

`dig @127.0.0.1 -p 1053 google.com A dig @127.0.0.1 -p 1053 google.com AAAA dig @127.0.0.1 -p 1053 gmail.com MX`

TCP:

`dig +tcp @127.0.0.1 -p 1053 example.com A`

---

## 🧪 Ejecutar tests

### Tests normales (forwarder)

`cargo test`

### Tests de integración DNS

`cargo test --test dns_integration -- --nocapture`

### Tests de recursor iterativo (requiere Internet)

`cargo test --test dns_integration -- --nocapture --ignored`

---

## 🛠 Recomendaciones en desarrollo

- Usar puertos >1024

- Empezar en modo forwarder

- Activar logs a nivel DEBUG

- No exponer el servicio a Internet sin hardening

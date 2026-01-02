# Bootstrap: roots + DNSSEC (Hickory Recursor)

Este documento describe cómo usar el binario **`recursor-bootstrap`** para mantener actualizados:

- **Root hints** (`root.hints` / `named.root`)
- **Trust anchor** para DNSSEC (`trusted-key.key`)

## Fuentes oficiales (IANA)

- **Root hints** (archivo `named.root`): provisto por InterNIC/IANA  
  https://www.internic.net/domain/named.root  
  (referenciado desde “Root Files” en IANA)

- **Root trust anchors** (índice + `root-anchors.xml` firmado):  
  https://www.iana.org/dnssec/files  
  https://data.iana.org/root-anchors/

- Especificación del mecanismo y formato: **RFC 9718**  
  https://www.rfc-editor.org/rfc/rfc9718.html

- Manual de Hickory (formato esperado para `root.hints` y `trusted-key.key`):  
  https://hickory-dns.org/book/hickory/recursive_resolver.html

> Nota: Hickory documenta `trusted-key.key` como líneas **DNSKEY** (zona “.”), normalmente copiadas de un `dig DNSKEY . +answer`.

---

## Uso

### 1) Descargar root hints (IANA named.root)

```bash
recursor-bootstrap fetch-roots --out /etc/rustdns/root.hints
```

### 2) Si tu config usa `roots = ["IP", ...]` (en vez de path), extraer IPs

```bash
recursor-bootstrap extract-root-ips --input /etc/rustdns/root.hints --out-toml /etc/rustdns/roots.auto.toml
```

Esto genera un snippet:

```toml
roots = ["198.41.0.4", "2001:503:ba3e::2:30", ...]
```

Luego lo incluís/copias en tu `config.toml` o lo mergeás en tu sistema de deploy.

### 3) Generar trust anchor para Hickory (`trusted-key.key`)

```bash
recursor-bootstrap make-trust-anchor --out /etc/rustdns/trusted-key.key
```

Por defecto consulta `DNSKEY .` usando `1.1.1.1:53`. Podés indicar resolvers alternativos:

```bash
recursor-bootstrap make-trust-anchor \
  --out /etc/rustdns/trusted-key.key \
  --resolver 1.1.1.1:53 \
  --resolver 8.8.8.8:53
```

> Recomendación: usar más de un resolver y dejar el primero que responda.

---

## Cómo apuntar tu recursor a estos archivos

### Opción A (estilo Hickory config.toml)

Hickory indica que en `config.toml` se usen paths absolutos:

```toml
[[zones]]
zone = "."
zone_type = "Hint"
stores = { type = "recursor",
           roots = "/etc/rustdns/root.hints",
           dnssec_policy.ValidateWithStaticKey.path = "/etc/rustdns/trusted-key.key" }
```

### Opción B (tu engine actual con `roots = ["IP", ...]`)

- mantenés `config.toml` con `roots = [...]`
- corrés `extract-root-ips` y volcás el array donde lo necesitás

---

## systemd timer (recomendado)

### Servicio: `/etc/systemd/system/recursor-bootstrap.service`

```ini
[Unit]
Description=Actualizar root hints y trust anchor DNSSEC

[Service]
Type=oneshot
ExecStart=/usr/local/bin/recursor-bootstrap fetch-roots --out /etc/rustdns/root.hints
ExecStart=/usr/local/bin/recursor-bootstrap make-trust-anchor --out /etc/rustdns/trusted-key.key --resolver 1.1.1.1:53 --resolver 8.8.8.8:53
```

### Timer: `/etc/systemd/system/recursor-bootstrap.timer`

```ini
[Unit]
Description=Ejecutar bootstrap semanal de DNS roots/DNSSEC

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

Activar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now recursor-bootstrap.timer
```

---

## Cron (alternativa rápida)

```cron
0 3 * * 1 /usr/local/bin/recursor-bootstrap fetch-roots --out /etc/rustdns/root.hints && \
          /usr/local/bin/recursor-bootstrap make-trust-anchor --out /etc/rustdns/trusted-key.key --resolver 1.1.1.1:53 --resolver 8.8.8.8:53
```

---

## Seguridad / buenas prácticas

- Guardá estos archivos con permisos restrictivos (root:root 0644 suele alcanzar).
- Si habilitás DNSSEC validation, mantené Hickory actualizado (hubo fixes de validación en versiones históricas).
- Si querés harden “full compliance”, podés verificar la firma S/MIME (`root-anchors.p7s` + `icannbundle.pem`) antes de confiar en `root-anchors.xml`.

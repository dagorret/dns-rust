# rust-dns-recursor (proyecto completo y prolijo)

Servidor DNS en Rust con:

- **Zonas locales** (overrides) desde `zones/*.toml`
- **Filtros** (allow/block por dominio) + hardening por redes IP destino
- **Cache frontal** (positivo + negativo) con TTL clamp
- **Dos modos de resolución** (selección automática por config):
  - **Forwarder** (si `upstreams` está presente): reenvía a DNS de la red (ej. universidad)
  - **Recursor iterativo** (si `upstreams` NO está): iterativo desde *root hints* (sin DNSSEC por defecto)
- (Opcional) **DNSSEC** para el modo iterativo: `--features dnssec` y `dnssec=process|validate`

> En redes donde solo permiten salir a DNS institucional (como la universidad),
> **tenés que usar modo Forwarder**, porque un recursor iterativo necesita hablar con root/TLD/autoritativos (muchas IPs).

## Ejecutar

```bash
cargo run -- -c config/example.toml
```

Por defecto escucha en `0.0.0.0:5353`.

## Probar (forwarder)

```bash
dig @127.0.0.1 -p 5353 www.unrc.edu.ar A
```

Confirmar tráfico:

```bash
sudo tcpdump -ni any 'port 53'
```

Deberías ver salida SOLO a las IPs definidas en `upstreams`.

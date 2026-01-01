# Configuración del sistema

Este proyecto implementa un **servidor DNS robusto en Rust**, capaz de operar en dos modos principales:

- **Modo Forwarder (Upstream)**
- **Modo Recursor Iterativo (Full Recursive)**

La configuración se realiza mediante archivos TOML ubicados en el directorio `config/`.

---

## 📁 Estructura de configuración

```text
config/
├── up.toml        # Ejemplo: modo forwarder (con upstreams)
├── recursor.toml  # Ejemplo: modo recursor iterativo
├── example.toml   # Configuración de referencia
```

## ⚙️ Parámetros principales

### Puertos y listeners

`listen_udp = "0.0.0.0:1053" listen_tcp = "0.0.0.0:1053"`

- Soporta **UDP y TCP**

- En desarrollo se recomienda usar puertos >1024

---

## 🔁 Modo Forwarder (Upstream)

`upstreams = ["1.1.1.1:53", "8.8.8.8:53"]`

- El servidor **no realiza recursión**

- Reenvía consultas a resolvers externos

- Ideal para:
  
  - Redes corporativas
  
  - Entornos con restricciones
  
  - Máximo rendimiento y simplicidad

---

## 🌐 Modo Recursor Iterativo (Full Recursive)

`roots = [  "198.41.0.4",  "199.9.14.201",  "192.33.4.12" ]`

- El servidor:
  
  - Consulta root servers
  
  - Resuelve TLDs
  
  - Contacta servidores autoritativos

- **No depende de upstreams externos**

- Requiere salida a Internet por UDP/53

---

## 🧠 Cache DNS

`[cache] answer_cache_size = 20000 negative_cache_size = 5000 min_ttl = 5 max_ttl = 86400 negative_ttl = 300`

- Cache positiva (respuestas válidas)

- Cache negativa (NXDOMAIN)

- TTL mínimo y máximo configurables

---

## 🚫 Filtros

`[filters] blocklist_domains = ["ads.example", "tracking.example"] deny_nets = ["10.0.0.0/8", "192.168.0.0/16"]`

- Blocklist de dominios

- Filtros por redes IP

- Ideal para control, seguridad y privacidad

---

## 🧪 Zonas locales

`[zones] zones_dir = "zones"`

- Permite servir zonas locales

- Útil para:
  
  - Testing
  
  - Entornos internos
  
  - Overrides DNS

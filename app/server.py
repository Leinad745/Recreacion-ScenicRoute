"""
5ub4k3m1's inc. - Monitoreo de disponibilidad
Recreación del reto "The Scenic Route" (SSRF -> open redirect -> control plane).

Un solo proceso levanta TRES piezas co-locadas en el mismo host (como el original):
  - App pública        -> 0.0.0.0:8080   (dashboard, /monitors, /go, /static)
  - Control plane      -> 127.0.0.1:9101 (loopback-only, sin auth, tiene la flag)
  - Probe              -> tarea de fondo que busca los monitores cada N segundos

La vulnerabilidad: el probe SIGUE los redirects sin re-validar el destino, así que
un open redirect (/go?next=) alojado en el dominio permitido evade el filtro
anti-SSRF y alcanza el control plane interno.
"""
import asyncio
import html
import ipaddress
import os
import socket
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
FLAG = os.environ.get("FLAG", "flag{sub4k3m1_kn0w5_d4_r0ut3}")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "sub4k3m1.status.monitor")
PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", "8080"))
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "9101"))
PROBE_INTERVAL = int(os.environ.get("PROBE_INTERVAL", "15"))
STATIC_DIR = Path(__file__).parent / "static"

# Egress del probe: SOLO estas redes son alcanzables (loopback + la subred del
# propio contenedor). Todo lo demás -incluida la LAN del host y otras privadas-
# se descarta, para que exponer el reto en red no lo convierta en un pivote SSRF.
ALLOWED_NETS = [
    ipaddress.ip_network(n.strip())
    for n in os.environ.get(
        "PROBE_ALLOWED_NETS", "127.0.0.0/8,::1/128,172.28.0.0/24"
    ).split(",")
    if n.strip()
]

# El filtro confía en su propio dominio (allowlist por hostname). Esa confianza,
# combinada con el open redirect que vive ahí, es el fallo de diseño explotable.
ALLOWED_HOSTS = {PUBLIC_HOST.lower(), "www." + PUBLIC_HOST.lower()}

# Estado en memoria: lista de monitores del "usuario" (arranca vacía).
MONITORS: list[dict] = []

# --------------------------------------------------------------------------- #
# Resolución de nombres tolerante a codificaciones (para el filtro)
# --------------------------------------------------------------------------- #
def literal_ip(host: str) -> ipaddress._BaseAddress | None:
    """Si `host` es una IP literal en CUALQUIER notación (dotted, IPv6, entero
    decimal, hex, octal, forma corta), devuelve la IP; si es un dominio, None."""
    h = host.strip("[]")  # IPv6 entre corchetes
    # dotted v4 / v6: 127.0.0.1, ::1
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # entero decimal: 2130706433
    if h.isdigit():
        try:
            return ipaddress.ip_address(int(h))
        except ValueError:
            pass
    # hex / octal / formas cortas via inet_aton: 0x7f000001, 0177.0.0.1, 127.1
    try:
        return ipaddress.ip_address(socket.inet_aton(h))
    except OSError:
        return None


def resolve_all(host: str) -> list[ipaddress._BaseAddress]:
    """TODAS las IPs candidatas de `host`: literal (cualquier notación) o DNS."""
    lit = literal_ip(host)
    if lit is not None:
        return [lit]
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out: list = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


def is_internal(ip: ipaddress._BaseAddress) -> bool:
    """No globalmente enrutable = interno (privada / loopback / link-local / reservada)."""
    return not ip.is_global


def reachable(ip: ipaddress._BaseAddress) -> bool:
    """El probe solo alcanza las redes de ALLOWED_NETS (loopback + subred propia)."""
    return any(ip.version == net.version and ip in net for net in ALLOWED_NETS)


# --------------------------------------------------------------------------- #
# Filtro anti-SSRF (SOLO en el registro del monitor)
# --------------------------------------------------------------------------- #
def validate_registration(url: str) -> str | None:
    """Devuelve un mensaje de error si la URL debe rechazarse, o None si se acepta.

    Regla: solo se aceptan DOMINIOS públicos. Toda IP literal se rechaza (las
    privadas/loopback con 'private address blocked'), y todo dominio que resuelva
    a una IP privada también se bloquea.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "solo se admiten endpoints http/https"
    host = parsed.hostname
    if not host:
        return "url inválida"

    # No se admiten IPs literales: solo dominios.
    lit = literal_ip(host)
    if lit is not None:
        return "dirección privada bloqueada" if is_internal(lit) else "no se admiten IP literales; registra un dominio"

    # Allowlist del dominio propio: se acepta sin resolver (el fallo de diseño:
    # un dominio de confianza que además aloja un open redirect).
    if host.lower() in ALLOWED_HOSTS:
        return None

    ips = resolve_all(host)
    if not ips:
        return "no se pudo resolver el host"
    for ip in ips:
        if is_internal(ip):  # p. ej. un dominio que apunta a una IP privada
            return "dirección privada bloqueada"
    return None


# --------------------------------------------------------------------------- #
# Probe: busca cada monitor. SIGUE redirects SIN re-validar (la vulnerabilidad).
# Política de egress: solo alcanza direcciones internas; público -> timeout.
# --------------------------------------------------------------------------- #
async def probe_once(client: httpx.AsyncClient, url: str) -> tuple[object, str]:
    cur = url
    for _ in range(6):  # límite de saltos
        parsed = urlparse(cur)
        host = parsed.hostname or ""
        ips = resolve_all(host)
        if not ips:
            return "down", "ConnectError: name resolution failed"

        # Egress policy (equivalente a un firewall de salida): la red del probe
        # solo alcanza loopback + su propia subred. Cualquier otro destino
        # (público, la LAN del host, otras privadas) se descarta -> timeout.
        if not any(reachable(ip) for ip in ips):
            return "down", "ConnectTimeout: timed out"

        try:
            # follow_redirects=False: seguimos a mano, y NUNCA re-validamos -> SSRF.
            resp = await client.get(cur, follow_redirects=False, timeout=4.0)
        except httpx.ConnectError:
            return "down", "ConnectError: [Errno 111] Connection refused"
        except httpx.TimeoutException:
            return "down", "ConnectTimeout: timed out"
        except Exception as exc:  # noqa: BLE001
            return "down", f"{type(exc).__name__}: {exc}"

        if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
            cur = urljoin(cur, resp.headers["location"])
            continue
        return resp.status_code, resp.text[:512]
    return "down", "too many redirects"


async def probe_loop():
    async with httpx.AsyncClient() as client:
        while True:
            for mon in MONITORS:
                if mon.get("blocked"):
                    continue  # rechazado por el filtro en el registro: nunca se sondea
                code, body = await probe_once(client, mon["url"])
                mon["code"], mon["body"] = code, body
                mon["checked"] = time.strftime("%H:%M:%S UTC", time.gmtime())
            await asyncio.sleep(PROBE_INTERVAL)


# --------------------------------------------------------------------------- #
# App pública (dashboard + /monitors + /go + /static)
# --------------------------------------------------------------------------- #
public = FastAPI(title="5ub4k3m1 status", docs_url=None, redoc_url=None)
public.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def render_monitor(mon: dict) -> str:
    code = mon["code"]
    if code is None:
        badge, cls = "…", "pending"
    elif code == "down":
        badge, cls = "down", "down"
    elif isinstance(code, int) and 200 <= code < 400:
        badge, cls = str(code), "ok"
    else:
        badge, cls = str(code), "warn"
    checked = mon["checked"] or "pendiente"
    return (
        f'<article class="mon"><div class="head">'
        f'<code>{html.escape(mon["url"])}</code>'
        f'<span class="code {cls}">{html.escape(badge)}</span></div>'
        f'<pre>{html.escape(mon["body"] or "")}</pre>'
        f'<div class="small">checked {html.escape(checked)}</div></article>'
    )


def render_page() -> str:
    cards = "".join(render_monitor(m) for m in reversed(MONITORS))
    tpl = (STATIC_DIR / "index.template.html").read_text(encoding="utf-8")
    return tpl.replace("<!--MONITORS-->", cards)


@public.get("/", response_class=HTMLResponse)
def index():
    return render_page()


@public.get("/health")
def health():
    return {"status": "ok"}


@public.post("/monitors")
def add_monitor(url: str = Form(...)):
    error = validate_registration(url)
    if error:
        MONITORS.append({"url": url, "code": "down", "body": error, "blocked": True,
                         "checked": time.strftime("%H:%M:%S UTC", time.gmtime())})
    else:
        MONITORS.append({"url": url, "code": None, "body": "", "checked": None})
    return RedirectResponse("/", status_code=303)


@public.get("/go")
def go(next: str = ""):
    """Attribution hop: registra el clic y hace 302 al destino. Open redirect."""
    return RedirectResponse(next, status_code=302)


# --------------------------------------------------------------------------- #
# Control plane interno (bind 127.0.0.1:9101, sin autenticación)
# --------------------------------------------------------------------------- #
control = FastAPI(title="s4k3m1-control-plane", docs_url=None, redoc_url=None)


@control.get("/")
def cp_root():
    return JSONResponse({
        "service": "s4k3m1-control-plane",
        "release": "2.4.11",
        "bind": f"127.0.0.1:{CONTROL_PORT}",
        "api": "/v1/",
    })


@control.get("/v1/")
def cp_v1():
    return JSONResponse({"endpoints": ["/v1/monitors", "/v1/secrets"]})


@control.get("/v1/monitors")
def cp_monitors():
    return JSONResponse({
        "fleet": ["bog1", "scl2", "gru1"],
        "note": "registro interno de la flota de probes; los secretos están en /v1/secrets",
    })


@control.get("/v1/secrets")
def cp_secrets():
    return JSONResponse({
        "issuer": "s4k3m1-control-plane",
        "flag": FLAG,
        "rotated": "2026-09-26T00:00:00Z",
    })


# --------------------------------------------------------------------------- #
# Arranque: dos servidores uvicorn + el probe, todo en un proceso
# --------------------------------------------------------------------------- #
async def main():
    public_cfg = uvicorn.Config(public, host="0.0.0.0", port=PUBLIC_PORT, log_level="info")
    # Control plane SOLO en loopback: por eso "solo los probes lo ven".
    control_cfg = uvicorn.Config(control, host="127.0.0.1", port=CONTROL_PORT, log_level="warning")
    servers = [uvicorn.Server(public_cfg), uvicorn.Server(control_cfg)]
    await asyncio.gather(
        servers[0].serve(),
        servers[1].serve(),
        probe_loop(),
    )


if __name__ == "__main__":
    asyncio.run(main())

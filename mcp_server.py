#!/usr/bin/env python3
"""mcp_server.py - the certificate MCP server as an embeddable object.

The GUI hosts this in a background thread, so the whole product is one exe:
no second binary, no console window.  `nixgc_cert_mcp.py` remains a thin CLI
wrapper for people who want a standalone process.

  host = MCPHost(port=8765)
  host.start()        # background thread, returns immediately
  host.status()       # {'running': True, 'url': 'http://127.0.0.1:8765/mcp'}
  host.stop()
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import threading
import time
import traceback

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from mcp.server.mcpserver import MCPServer

from certstore import CertStore, TEMPLATES, Template, app_root

ISSUED_DIR = app_root() / "issued"

# --------------------------------------------------------------------------
# shared state
# --------------------------------------------------------------------------

_lock = threading.Lock()
_store: CertStore | None = None


def store() -> CertStore:
    global _store
    with _lock:
        if _store is None:
            _store = CertStore()
            _store.load_all()
        return _store


def reload_store_internal() -> CertStore:
    global _store
    with _lock:
        _store = CertStore()
        _store.load_all()
        return _store


def template_by_name(name: str) -> Template:
    for t in TEMPLATES:
        if t.name == name:
            return t
    raise ValueError(f"unknown template {name!r}; known: {[t.name for t in TEMPLATES]}")


def _find_issuer(issuer: str):
    st = store()
    cands = [k for k in st.ca_keys if k.cert is not None]
    if not cands:
        raise ValueError("no CA key with a certificate is available")
    for k in cands:
        if k.path == issuer:
            return k
    exact = [k for k in cands if k.common_name == issuer]
    if len(exact) == 1:
        return exact[0]
    partial = [k for k in cands if issuer.lower() in k.common_name.lower()]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise ValueError(
            f"no issuer matched {issuer!r}; available: {[k.common_name for k in cands]}"
        )
    raise ValueError(
        f"issuer {issuer!r} is ambiguous; matches: {[k.common_name for k in partial]}"
    )


def _resolve_cert(target: str):
    st = store()
    p = pathlib.Path(target)
    if p.exists():
        blob = p.read_bytes()
        try:
            cert = x509.load_pem_x509_certificate(blob)
        except Exception:
            cert = x509.load_pem_x509_certificates(blob)[0]
        return st._add_cert(cert, str(p), "mcp")

    if "|" in target:
        subj, iss = (part.strip() for part in target.split("|", 1))
        matches = [c for c in st.certs if c.common_name == subj and c.issuer_cn == iss]
        if len(matches) == 1:
            return matches[0]
        raise ValueError(
            f"subject|issuer {target!r} matched {len(matches)}; issuers present: "
            f"{sorted({c.issuer_cn for c in st.certs if c.common_name == subj})}"
        )

    exact = [c for c in st.certs if c.common_name == target]
    if not exact:
        exact = [c for c in st.certs if target.lower() in c.common_name.lower()]
    if not exact:
        raise ValueError(f"no certificate matched {target!r}")
    if len(exact) == 1:
        return exact[0]

    with_key = [c for c in exact if c.key_path]
    if len(with_key) == 1:
        return with_key[0]
    pool = with_key or exact
    known = {c.common_name for c in st.certs}
    chained = [c for c in pool if c.issuer_cn in known]
    if len(chained) == 1:
        return chained[0]
    pool = chained or pool
    if len(pool) == 1:
        return pool[0]
    raise ValueError(
        f"{target!r} matched {len(pool)} certificates; disambiguate with "
        f"'<subject>|<issuer>'. candidates: "
        + ", ".join(f"{c.common_name}|{c.issuer_cn}" for c in pool)
    )


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------


def list_issuers() -> str:
    """List every CA private key available for signing, with curve, serial and
    expiry. Use this first to pick an issuer."""
    st = store()
    out = []
    for k in st.ca_keys:
        if k.cert is None:
            continue
        out.append(
            {
                "common_name": k.common_name,
                "path": k.path,
                "curve": k.curve,
                "serial_hex": k.serial_hex,
                "expires": k.not_after.date().isoformat() if k.not_after else None,
                "revoked": bool(k.cert.revoked),
                "eku": list(k.cert.eku),
            }
        )
    return json.dumps({"count": len(out), "issuers": out}, indent=2, ensure_ascii=False)


def list_templates() -> str:
    """List the certificate templates (profiles) that can be passed to
    issue_certificate, with their CA flag, path length and EKU."""
    return json.dumps(
        {
            "templates": [
                {
                    "name": t.name,
                    "description": t.description,
                    "is_ca": t.is_ca,
                    "path_length": t.path_length,
                    "eku": list(t.eku),
                }
                for t in TEMPLATES
            ]
        },
        indent=2,
        ensure_ascii=False,
    )


def issue_certificate(
    common_name: str,
    issuer: str = "",
    template: str = "TLS 伺服器",
    organization: str = "",
    org_unit: str = "",
    country: str = "",
    sans: str = "",
    days: int = 365,
    serial_hex: str = "",
    save: bool = True,
) -> str:
    """Issue a new certificate signed by an available CA key. Returns the
    subject, serial, validity, on-disk paths and the PEM text. common_name is
    required; sans is a comma-separated list of DNS names and/or IP addresses.
    template defaults to the TLS server profile."""
    st = store()
    if issuer:
        ca = _find_issuer(issuer)
    else:
        cands = [k for k in st.ca_keys if k.cert is not None and not k.cert.revoked]
        if not cands:
            cands = [k for k in st.ca_keys if k.cert is not None]
        if not cands:
            raise ValueError("no CA key available")
        ca = cands[0]

    tpl = template_by_name(template)
    san_list = [s.strip() for s in sans.split(",") if s.strip()]
    cert, key = st.mint_leaf(
        ca,
        tpl,
        common_name=common_name,
        organization=organization,
        org_unit=org_unit,
        country=country,
        sans=san_list,
        days=days,
        serial_hex=serial_hex or None,
    )

    result: dict = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_hex": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "template": tpl.name,
        "is_ca": tpl.is_ca,
        "eku": list(tpl.eku),
        "curve": ca.curve,
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }

    if save:
        stem = "".join(c if c.isalnum() or c in "._-" else "_" for c in common_name)
        stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        cp, kp = st.save_issued(cert, key, ISSUED_DIR, f"{stem}_{stamp}")
        result["cert_path"] = str(cp)
        result["key_path"] = str(kp)

    chain = st.verify_chain(st._add_cert(cert, "(memory)", "mcp"))
    result["chain"] = [{"subject": s, "ok": ok, "note": note} for s, ok, note in chain]
    return json.dumps(result, indent=2, ensure_ascii=False)


def create_csr(
    common_name: str,
    key: str = "",
    organization: str = "",
    org_unit: str = "",
    country: str = "",
    sans: str = "",
) -> str:
    """Generate a CSR (certificate signing request) from an existing key and
    write it to csr/. Returns the PEM and path."""
    st = store()
    if key:
        k = st.key_by_path(key)
        if k is None:
            matches = [x for x in st.keys if key.lower() in x.key_name.lower()]
            if len(matches) != 1:
                raise ValueError(f"key {key!r} not found or ambiguous")
            k = matches[0]
    else:
        k = next((x for x in st.keys if x.cert is not None), None)
        if k is None:
            raise ValueError("no key available")

    csr = st.create_csr(
        k,
        common_name=common_name,
        organization=organization,
        org_unit=org_unit,
        country=country,
        sans=[s.strip() for s in sans.split(",") if s.strip()],
    )
    out = app_root() / "csr"
    out.mkdir(exist_ok=True)
    stem = "".join(c if c.isalnum() or c in "._-" else "_" for c in common_name)
    path = out / f"{stem}.csr.pem"
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return json.dumps(
        {
            "subject": csr.subject.rfc4514_string(),
            "signature_valid": csr.is_signature_valid,
            "path": str(path),
            "pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        },
        indent=2,
        ensure_ascii=False,
    )


def sign_csr(
    csr_path: str,
    issuer: str = "",
    template: str = "TLS 伺服器",
    days: int = 365,
    save: bool = True,
) -> str:
    """Sign an existing CSR file with an available CA key. The CSR's subject,
    SAN and public key are preserved."""
    st = store()
    p = pathlib.Path(csr_path)
    if not p.exists():
        raise ValueError(f"CSR not found: {csr_path}")
    csr = x509.load_pem_x509_csr(p.read_bytes())
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    ca = _find_issuer(issuer) if issuer else next(
        (k for k in st.ca_keys if k.cert is not None), None
    )
    if ca is None:
        raise ValueError("no CA key available")

    cert = st.sign_csr(ca, csr, template_by_name(template), days=days)
    result = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_hex": format(cert.serial_number, "X"),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }
    if save:
        ISSUED_DIR.mkdir(exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        cp = ISSUED_DIR / f"{p.stem}_{stamp}.crt.pem"
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        st._add_cert(cert, str(cp), "mcp-csr")
        result["cert_path"] = str(cp)
    return json.dumps(result, indent=2, ensure_ascii=False)


def inspect_certificate(target: str) -> str:
    """Build and verify the chain for a certificate. Accepts a file path, an
    exact common name, a substring, or 'subject|issuer' to disambiguate (the
    same key is often cross-signed by two CAs). Returns each hop and whether
    the signature holds."""
    st = store()
    entry = _resolve_cert(target)
    import base64

    chain = st.verify_chain(entry)
    return json.dumps(
        {
            "subject": entry.cert.subject.rfc4514_string(),
            "issuer": entry.cert.issuer.rfc4514_string(),
            "issuer_cn": entry.issuer_cn,
            "serial_hex": entry.serial_hex,
            "not_before": entry.not_before.isoformat(),
            "not_after": entry.not_after.isoformat(),
            "days_left": entry.days_left,
            "is_ca": entry.is_ca,
            "path_length": entry.path_length,
            "eku": list(entry.eku),
            "curve": entry.curve,
            "has_private_key": bool(entry.key_path),
            "revoked": entry.revoked,
            "chain": [{"subject": s, "ok": ok, "note": n} for s, ok, n in chain],
            "pem": entry.pem.decode("ascii"),
            "der_b64": base64.b64encode(
                entry.cert.public_bytes(serialization.Encoding.DER)
            ).decode("ascii"),
        },
        indent=2,
        ensure_ascii=False,
    )


def export_chain_bundle(target: str, include_root: bool = True) -> str:
    """Return a complete PEM bundle for a certificate: leaf first, then every
    intermediate up to (and optionally including) the root. Ready to drop into
    a TLS server config."""
    st = store()
    entry = _resolve_cert(target)

    chain = st.verify_chain(entry)
    pems = [entry.pem]
    current = entry
    seen = {entry.sha256}
    subjects = [entry.common_name]
    while True:
        issuer = st._find_issuer(current)
        if issuer is None or issuer.sha256 in seen:
            break
        seen.add(issuer.sha256)
        subjects.append(issuer.common_name)
        if issuer.self_signed:
            if include_root:
                pems.append(issuer.pem)
            break
        pems.append(issuer.pem)
        current = issuer

    return json.dumps(
        {
            "chain_ok": all(ok for _s, ok, _n in chain),
            "subjects": subjects,
            "pem_bundle": b"".join(pems).decode("ascii"),
        },
        indent=2,
        ensure_ascii=False,
    )


def reload_store() -> str:
    """Reload the certificate store from disk. Call after issuing files
    externally or after adding PEMs by hand."""
    st = reload_store_internal()
    return json.dumps(
        {
            "certs": len(st.certs),
            "keys": len(st.keys),
            "ca_keys": len(st.ca_keys),
            "revocations": len(st.revocations),
        },
        indent=2,
    )


TOOL_FUNCS = [
    list_issuers,
    list_templates,
    issue_certificate,
    create_csr,
    sign_csr,
    inspect_certificate,
    export_chain_bundle,
    reload_store,
]


def _log_tool_error(name: str, exc: BaseException) -> None:
    """Append a tool failure to mcp.log so a silent client error is diagnosable."""
    try:
        path = app_root() / "mcp.log"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n=== {dt.datetime.now().isoformat()} tool={name} ===\n")
            fh.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    except Exception:
        pass


def _wrap_tool(fn):
    """Log and re-raise tool exceptions with the real message attached."""
    import functools

    @functools.wraps(fn)
    def inner(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            _log_tool_error(fn.__name__, exc)
            raise RuntimeError(f"{fn.__name__} failed: {exc}") from exc

    return inner


def build_server(name: str = "nixgc-cert") -> MCPServer:
    """Construct a fresh MCPServer with every tool registered."""
    server = MCPServer(
        name=name,
        title="nixgc certificate manager",
        version="1.1.0",
        instructions=(
            "On-demand X.509 certificate generation. Call list_issuers to see "
            "which CA keys are available, then issue_certificate to mint a leaf. "
            "Templates: " + ", ".join(t.name for t in TEMPLATES) + "."
        ),
    )
    for fn in TOOL_FUNCS:
        wrapped = _wrap_tool(fn)
        server.add_tool(wrapped, name=fn.__name__, description=fn.__doc__)
    return server


# --------------------------------------------------------------------------
# embeddable host
# --------------------------------------------------------------------------


class MCPHost:
    """Runs the MCP HTTP server in a daemon thread inside the host process.

    Uvicorn only installs signal handlers on the main thread, so the server
    has to be stopped by flipping `should_exit` rather than by a signal.
    """

    def __init__(self, port: int = 8765, host: str = "127.0.0.1") -> None:
        self.port = port
        self.host = host
        self._thread: threading.Thread | None = None
        self._server = None
        self._error: str | None = None
        self._started_at: float | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/mcp"

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        return {
            "running": self.running(),
            "url": self.url,
            "port": self.port,
            "host": self.host,
            "error": self._error,
            "uptime_s": (
                round(time.time() - self._started_at, 1) if self._started_at else None
            ),
        }

    def start(self) -> bool:
        if self.running():
            return True
        self._error = None
        self._thread = threading.Thread(
            target=self._serve, name="nixgc-mcp", daemon=True
        )
        self._thread.start()
        # wait for uvicorn to bind (or fail) before reporting success
        for _ in range(100):
            if self._server is not None or self._error:
                break
            time.sleep(0.05)
        for _ in range(60):
            if self._error:
                return False
            if self._server is not None and getattr(
                self._server, "started", False
            ):
                self._started_at = time.time()
                return True
            time.sleep(0.05)
        return self.running()

    def _serve(self) -> None:
        try:
            import logging

            import uvicorn

            # A windowed build has no console: sys.stdout and sys.stderr are
            # None, and uvicorn's default log config calls .isatty() on them.
            # Skipping the dictConfig entirely (log_config=None) is what makes
            # the embedded server survive in a --windowed exe.
            for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "mcp"):
                logging.getLogger(name).setLevel(logging.CRITICAL)

            server = build_server()
            app = server.streamable_http_app(json_response=True)
            config = uvicorn.Config(
                app,
                host=self.host,
                port=self.port,
                log_config=None,
                log_level="critical",
                access_log=False,
            )
            uv = uvicorn.Server(config)
            self._server = uv
            uv.run()
        except Exception:
            self._error = traceback.format_exc(limit=8)

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.should_exit = True
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=8)
        self._thread = None
        self._server = None
        self._started_at = None

    def restart(self, port: int | None = None, host: str | None = None) -> bool:
        self.stop()
        if port is not None:
            self.port = port
        if host is not None:
            self.host = host
        return self.start()


# --------------------------------------------------------------------------
# Claude Desktop / generic MCP client config snippet
# --------------------------------------------------------------------------


def client_config(host: MCPHost) -> dict:
    return {
        "mcpServers": {
            "nixgc-cert": {
                "type": "http",
                "url": host.url,
            }
        }
    }


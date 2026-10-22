#!/usr/bin/env python3
"""certstore.py - data layer for the certificate/key manager GUI.

Loads every certificate and private key it can find under the project,
pairs keys to certs by public-key equality, and can mint new leaves under
any CA key it holds.

Nothing here touches the display; cert_manager.py is the GUI on top.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import random
import re
import sys
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = pathlib.Path(__file__).resolve().parent


def app_root() -> pathlib.Path:
    """Directory the data files live in.

    Running from source that is this file's directory.  Running as a frozen
    PyInstaller exe, __file__ points inside the bundle (or the _internal
    folder for onedir), so the data has to be resolved from the executable
    instead - otherwise the store would look for emudhra/ inside the package
    and find nothing.
    """
    if getattr(sys, "frozen", False):
        return pathlib.Path(sys.executable).resolve().parent
    return HERE

# --------------------------------------------------------------------------
# certificate profiles ("模板")
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Template:
    name: str
    description: str
    is_ca: bool
    path_length: int | None
    eku: tuple[str, ...]
    key_usage_sign: bool = True
    key_usage_encipher: bool = False


TEMPLATES: tuple[Template, ...] = (
    Template(
        "TLS 伺服器",
        "一般 HTTPS 伺服器憑證,serverAuth",
        is_ca=False,
        path_length=None,
        eku=("serverAuth",),
        key_usage_encipher=True,
    ),
    Template(
        "TLS 伺服器 + 用戶端",
        "雙向 TLS,serverAuth + clientAuth",
        is_ca=False,
        path_length=None,
        eku=("serverAuth", "clientAuth"),
        key_usage_encipher=True,
    ),
    Template(
        "用戶端認證",
        "僅 clientAuth",
        is_ca=False,
        path_length=None,
        eku=("clientAuth",),
    ),
    Template(
        "程式碼簽章",
        "codeSigning,用於簽執行檔",
        is_ca=False,
        path_length=None,
        eku=("codeSigning",),
    ),
    Template(
        "中間 CA",
        "可簽發下層憑證,pathlen=0",
        is_ca=True,
        path_length=0,
        eku=(),
    ),
    Template(
        "根 CA",
        "自簽根,pathlen=1",
        is_ca=True,
        path_length=1,
        eku=(),
    ),
)

EKU_MAP = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocspSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
}

EKU_SHORT = {
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "ocspSigning",
}


# --------------------------------------------------------------------------
# entries
# --------------------------------------------------------------------------


def _pub_fingerprint(pub) -> str:
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _curve_name(pub) -> str:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.curve.name
    if isinstance(pub, rsa.RSAPublicKey):
        return f"rsa{pub.key_size}"
    return type(pub).__name__


@dataclass
class CertEntry:
    sha256: str
    cert: x509.Certificate
    path: str
    source: str
    pem: bytes
    spki: str = ""
    curve: str = ""
    is_ca: bool = False
    path_length: int | None = None
    eku: tuple[str, ...] = ()
    internal_name: str = ""
    key_path: str | None = None
    key_fingerprint: str | None = None
    revoked: dict | None = None

    @property
    def common_name(self) -> str:
        for attr in self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            return str(attr.value)
        return self.cert.subject.rfc4514_string()

    @property
    def serial_hex(self) -> str:
        return format(self.cert.serial_number, "x").upper()

    @property
    def not_after(self) -> dt.datetime:
        return self.cert.not_valid_after_utc

    @property
    def not_before(self) -> dt.datetime:
        return self.cert.not_valid_before_utc

    @property
    def issuer_cn(self) -> str:
        for attr in self.cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
            return str(attr.value)
        return self.cert.issuer.rfc4514_string()

    @property
    def self_signed(self) -> bool:
        return self.cert.subject == self.cert.issuer

    @property
    def has_key(self) -> bool:
        return self.key_path is not None

    @property
    def days_left(self) -> int:
        return (self.not_after - dt.datetime.now(dt.timezone.utc)).days

    @property
    def expired(self) -> bool:
        return self.days_left < 0


@dataclass
class KeyEntry:
    path: str
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
    fingerprint: str
    curve: str
    source: str
    cert: CertEntry | None = None
    internal_name: str = ""

    @property
    def common_name(self) -> str:
        return self.cert.common_name if self.cert else "(未配對)"

    @property
    def key_name(self) -> str:
        stem = pathlib.Path(self.path).name
        for suffix in (".key.pem", ".pem", ".key"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        return stem

    @property
    def is_ca(self) -> bool:
        return bool(self.cert and self.cert.is_ca)

    @property
    def serial_hex(self) -> str:
        return self.cert.serial_hex if self.cert else ""

    @property
    def not_after(self) -> dt.datetime | None:
        return self.cert.not_after if self.cert else None


# --------------------------------------------------------------------------
# store
# --------------------------------------------------------------------------


class CertStore:
    def __init__(self, root: pathlib.Path | None = None) -> None:
        self.root = root if root is not None else app_root()
        self.certs: list[CertEntry] = []
        self.keys: list[KeyEntry] = []
        self.revocations: list[dict] = []
        self.templates: list[Template] = list(TEMPLATES)
        self._by_sha: dict[str, CertEntry] = {}
        self._by_spki: dict[str, CertEntry] = {}
        self._by_key_fp: dict[str, KeyEntry] = {}

    # -- loading ---------------------------------------------------------

    def load_all(self) -> None:
        self._load_emudhra_inventory()
        self._load_emudhra_roots()
        self._load_chain_files()
        self._load_pem_dirs()
        self._pair_keys()
        self._sort_certs()
        self._sort_keys()

    def _sort_keys(self) -> None:
        self.keys.sort(key=lambda k: k.key_name.lower())

    def _add_cert(self, cert: x509.Certificate, path: str, source: str,
                  revoked: dict | None = None) -> CertEntry | None:
        sha = cert.fingerprint(hashes.SHA256()).hex()
        if sha in self._by_sha:
            existing = self._by_sha[sha]
            if revoked and not existing.revoked:
                existing.revoked = revoked
            return existing
        try:
            pub = cert.public_key()
        except Exception:
            return None
        entry = CertEntry(
            sha256=sha,
            cert=cert,
            path=path,
            source=source,
            pem=cert.public_bytes(serialization.Encoding.PEM),
            spki=_pub_fingerprint(pub),
            curve=_curve_name(pub),
        )
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            entry.is_ca = bool(bc.ca)
            entry.path_length = bc.path_length
        except x509.ExtensionNotFound:
            pass
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            entry.eku = tuple(
                EKU_SHORT.get(o, getattr(o, "_name", o.dotted_string)) for o in eku
            )
        except x509.ExtensionNotFound:
            pass
        entry.internal_name = entry.common_name
        entry.revoked = revoked
        self.certs.append(entry)
        self._by_sha[sha] = entry
        self._by_spki.setdefault(entry.spki, entry)
        return entry

    def _load_emudhra_inventory(self) -> None:
        p = self.root / "emudhra" / "impacted-intermediates.json"
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return
        for item in data:
            pem = item.get("pem")
            if not pem:
                continue
            try:
                cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
            except Exception:
                continue
            rev = item.get("revocation")
            revoked = (
                {
                    "status": rev.get("status"),
                    "date": rev.get("date"),
                    "reason": rev.get("reason"),
                    "crl": rev.get("crl_url"),
                }
                if rev
                else None
            )
            e = self._add_cert(cert, str(p), "eMudhra 清單", revoked)
            if e:
                e.internal_name = item.get("name", e.internal_name)
            if revoked:
                self.revocations.append(
                    {
                        "name": item.get("name", e.common_name if e else ""),
                        "serial": item.get("serial_hex", ""),
                        "issuer": item.get("issuer", ""),
                        **revoked,
                    }
                )

    def _load_emudhra_roots(self) -> None:
        p = self.root / "emudhra" / "roots.json"
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return
        for item in data:
            pem = item.get("pem")
            if not pem:
                continue
            try:
                cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
            except Exception:
                continue
            e = self._add_cert(cert, str(p), "eMudhra 根")
            if e:
                e.internal_name = item.get("name", e.internal_name)

    def _load_chain_files(self) -> None:
        d = self.root / "emudhra" / "chains_extract" / "chains"
        if not d.is_dir():
            return
        for f in sorted(d.glob("*.pem")):
            try:
                chain = x509.load_pem_x509_certificates(f.read_bytes())
            except Exception:
                continue
            for c in chain:
                self._add_cert(c, str(f), f"鏈 {f.stem}")

    def _load_pem_dirs(self) -> None:
        for d in (
            self.root / "pki",
            self.root / "forged",
            self.root / "issued",
            self.root / "emudhra" / "repro",
        ):
            if not d.is_dir():
                continue
            for f in sorted(d.iterdir()):
                if not f.is_file():
                    continue
                name = f.name.lower()
                if name.endswith((".crt.pem", ".crt", ".cer", ".cert.pem")) or (
                    name.endswith(".pem") and ".key." not in name
                    and "chain" not in name
                ):
                    try:
                        for c in x509.load_pem_x509_certificates(f.read_bytes()):
                            self._add_cert(c, str(f), d.name)
                    except Exception:
                        continue
                if ".key." in name or name.endswith(".key"):
                    self._load_key(f, d.name)
        self._sort_certs()

    def _sort_certs(self) -> None:
        """Leaves first (newly issued on top), then CAs; alphabetical within."""
        self.certs.sort(key=lambda c: (c.is_ca, c.common_name.lower()))

    def _load_key(self, path: pathlib.Path, source: str) -> KeyEntry | None:
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        except Exception:
            return None
        if not isinstance(key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
            return None
        fp = _pub_fingerprint(key.public_key())
        if fp in self._by_key_fp:
            return self._by_key_fp[fp]
        entry = KeyEntry(
            path=str(path),
            key=key,
            fingerprint=fp,
            curve=_curve_name(key.public_key()),
            source=source,
        )
        self.keys.append(entry)
        self._by_key_fp[fp] = entry
        return entry

    def _pair_keys(self) -> None:
        for k in self.keys:
            cert = self._by_spki.get(k.fingerprint)
            if cert is not None:
                k.cert = cert
                k.internal_name = cert.internal_name
                cert.key_path = k.path
                cert.key_fingerprint = k.fingerprint

    # -- queries ---------------------------------------------------------

    @property
    def ca_keys(self) -> list[KeyEntry]:
        return [k for k in self.keys if k.is_ca]

    def cert_by_sha(self, sha: str) -> CertEntry | None:
        return self._by_sha.get(sha)

    def key_by_path(self, path: str) -> KeyEntry | None:
        for k in self.keys:
            if k.path == path:
                return k
        return None

    # -- minting ---------------------------------------------------------

    def mint_leaf(
        self,
        issuer: KeyEntry,
        template: Template,
        *,
        common_name: str,
        organization: str = "",
        org_unit: str = "",
        country: str = "",
        sans: list[str] | None = None,
        days: int = 365,
        serial_hex: str | None = None,
        reuse_key: bool = False,
    ) -> tuple[x509.Certificate, object]:
        """Sign a new certificate under `issuer`.  Returns (cert, private_key)."""
        if issuer.cert is None:
            raise ValueError("簽發者沒有對應的憑證")
        issuer_cert = issuer.cert.cert
        issuer_key = issuer.key

        if reuse_key:
            new_key = issuer_key
        elif isinstance(issuer_key, ec.EllipticCurvePrivateKey):
            new_key = ec.generate_private_key(issuer_key.curve)
        else:
            new_key = rsa.generate_private_key(
                public_exponent=65537, key_size=issuer_key.key_size
            )

        attrs = []
        if country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if organization:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if org_unit:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

        now = dt.datetime.now(dt.timezone.utc)
        if serial_hex:
            serial = int(serial_hex.replace(":", "").replace(" ", ""), 16)
        else:
            serial = random.getrandbits(127) | 1

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name(attrs))
            .issuer_name(issuer_cert.subject)
            .public_key(new_key.public_key())
            .serial_number(serial)
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(
                x509.BasicConstraints(ca=template.is_ca, path_length=template.path_length),
                critical=True,
            )
        )

        if template.is_ca:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        else:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=template.key_usage_sign,
                    content_commitment=False,
                    key_encipherment=template.key_usage_encipher,
                    data_encipherment=False,
                    key_agreement=template.key_usage_encipher,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )

        san_values: list[x509.GeneralName] = []
        for s in sans or []:
            s = s.strip()
            if not s:
                continue
            try:
                san_values.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                san_values.append(x509.DNSName(s))
        if san_values:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_values), critical=False
            )

        if template.eku:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([EKU_MAP[n] for n in template.eku if n in EKU_MAP]),
                critical=False,
            )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(new_key.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )

        if isinstance(issuer_key, ec.EllipticCurvePrivateKey):
            cert = builder.sign(issuer_key, hashes.SHA384())
        else:
            cert = builder.sign(issuer_key, hashes.SHA256())
        return cert, new_key

    # -- CSRs ------------------------------------------------------------

    def create_csr(
        self,
        key_entry: KeyEntry,
        *,
        common_name: str,
        organization: str = "",
        org_unit: str = "",
        country: str = "",
        sans: list[str] | None = None,
        hash_name: str = "sha384",
    ) -> x509.CertificateSigningRequest:
        attrs = []
        if country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if organization:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if org_unit:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(attrs)
        )
        san_values: list[x509.GeneralName] = []
        for s in sans or []:
            s = s.strip()
            if not s:
                continue
            try:
                san_values.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                san_values.append(x509.DNSName(s))
        if san_values:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_values), critical=False
            )
        algo = {"sha256": hashes.SHA256, "sha384": hashes.SHA384,
                "sha512": hashes.SHA512}[hash_name]
        return builder.sign(key_entry.key, algo())

    def sign_csr(
        self,
        issuer: KeyEntry,
        csr: x509.CertificateSigningRequest,
        template: Template,
        *,
        days: int = 365,
        serial_hex: str | None = None,
    ) -> x509.Certificate:
        """Issue a certificate for an existing CSR, keeping the CSR's key."""
        if issuer.cert is None:
            raise ValueError("簽發者沒有對應的憑證")
        if not csr.is_signature_valid:
            raise ValueError("CSR 簽章無效")
        issuer_cert = issuer.cert.cert
        issuer_key = issuer.key

        now = dt.datetime.now(dt.timezone.utc)
        serial = (
            int(serial_hex.replace(":", "").replace(" ", ""), 16)
            if serial_hex
            else random.getrandbits(127) | 1
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(issuer_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(
                x509.BasicConstraints(ca=template.is_ca, path_length=template.path_length),
                critical=True,
            )
        )
        if template.is_ca:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
        else:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=template.key_usage_sign,
                    content_commitment=False,
                    key_encipherment=template.key_usage_encipher,
                    data_encipherment=False,
                    key_agreement=template.key_usage_encipher,
                    key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )

        # carry the CSR's SAN over
        try:
            csr_san = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            builder = builder.add_extension(csr_san, critical=False)
        except x509.ExtensionNotFound:
            pass

        if template.eku:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([EKU_MAP[n] for n in template.eku if n in EKU_MAP]),
                critical=False,
            )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )

        if isinstance(issuer_key, ec.EllipticCurvePrivateKey):
            return builder.sign(issuer_key, hashes.SHA384())
        return builder.sign(issuer_key, hashes.SHA256())

    # -- writing ---------------------------------------------------------

    def save_issued(
        self,
        cert: x509.Certificate,
        key,
        out_dir: pathlib.Path,
        stem: str,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_path = out_dir / f"{stem}.crt.pem"
        key_path = out_dir / f"{stem}.key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        # register in the live store so the GUI updates immediately
        entry = self._add_cert(cert, str(cert_path), "新簽發")
        if entry:
            entry.internal_name = entry.common_name
            ke = KeyEntry(
                path=str(key_path),
                key=key,
                fingerprint=_pub_fingerprint(key.public_key()),
                curve=_curve_name(key.public_key()),
                source="新簽發",
            )
            ke.cert = entry
            ke.internal_name = entry.internal_name
            entry.key_path = str(key_path)
            entry.key_fingerprint = ke.fingerprint
            self.keys.append(ke)
            self._by_key_fp[ke.fingerprint] = ke
        return cert_path, key_path

    # -- verification ----------------------------------------------------

    def verify_chain(self, leaf: CertEntry) -> list[tuple[str, bool, str]]:
        """Walk issuer links up through the store.  Returns [(subject, ok, note)]."""
        steps: list[tuple[str, bool, str]] = []
        current = leaf
        seen: set[str] = set()
        while True:
            if current.sha256 in seen:
                steps.append((current.common_name, False, "循環鏈"))
                break
            seen.add(current.sha256)
            issuer = self._find_issuer(current)
            if issuer is None:
                if current.self_signed:
                    steps.append((current.common_name, True, "自簽根"))
                else:
                    steps.append((current.common_name, False, f"找不到簽發者 {current.issuer_cn}"))
                break
            try:
                pub = issuer.cert.public_key()
                if isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(
                        current.cert.signature,
                        current.cert.tbs_certificate_bytes,
                        ec.ECDSA(current.cert.signature_hash_algorithm),
                    )
                else:
                    from cryptography.hazmat.primitives.asymmetric import padding

                    pub.verify(
                        current.cert.signature,
                        current.cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        current.cert.signature_hash_algorithm,
                    )
                steps.append((current.common_name, True, f"由 {issuer.common_name} 簽發"))
            except Exception:
                steps.append((current.common_name, False, f"簽章不符 {issuer.common_name}"))
                break
            if issuer.self_signed:
                steps.append((issuer.common_name, True, "自簽根"))
                break
            current = issuer
        return steps

    def _find_issuer(self, cert: CertEntry) -> CertEntry | None:
        for c in self.certs:
            if c.cert.subject == cert.cert.issuer:
                return c
        return None


# --------------------------------------------------------------------------
# CLI smoke test
# --------------------------------------------------------------------------


def main() -> int:
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    store = CertStore()
    store.load_all()
    print(f"憑證 {len(store.certs)} 張,私鑰 {len(store.keys)} 把,"
          f"其中 CA 金鑰 {len(store.ca_keys)} 把")
    print(f"吊銷記錄 {len(store.revocations)} 筆\n")
    print(f"{'內部名稱':24s} {'CN':22s} {'密鑰':4s} {'CA':3s} {'序列號':20s} {'失效'}")
    print("-" * 104)
    for k in store.keys:
        c = k.cert
        print(
            f"{k.internal_name[:24]:24s} {k.common_name[:22]:22s} "
            f"{('yes' if c else 'no'):4s} {('yes' if k.is_ca else ''):3s} "
            f"{(k.serial_hex[:20] if k.serial_hex else ''):20s} "
            f"{k.not_after.date().isoformat() if k.not_after else ''}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


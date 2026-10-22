#!/usr/bin/env python3
"""build_exe.py - package the GUI and the MCP server into Windows executables.

Two targets:

  dist/NixGCCertManager.exe    windowed GUI, icon, no console
  dist/nixgc-cert-mcp.exe      console MCP server (stdio + HTTP)

PyInstaller is driven through its Python API so the build is reproducible
from one command and the icon/version resources are applied explicitly.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
DIST = HERE / "dist"
BUILD = HERE / "build"
ICON = HERE / "assets" / "icon.ico"

VERSION_INFO = """# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'nixgc'),
         StringStruct('FileDescription', 'nixgc certificate manager'),
         StringStruct('FileVersion', '1.0.0.0'),
         StringStruct('InternalName', 'NixGCCertManager'),
         StringStruct('LegalCopyright', 'nixgc'),
         StringStruct('OriginalFilename', 'NixGCCertManager.exe'),
         StringStruct('ProductName', 'nixgc certificate manager'),
         StringStruct('ProductVersion', '1.0.0.0')])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""

VERSION_INFO_MCP = VERSION_INFO.replace(
    "NixGCCertManager", "nixgc-cert-mcp"
).replace("nixgc certificate manager", "nixgc certificate MCP server")


def ensure_icon() -> pathlib.Path:
    if not ICON.exists():
        print("[build] icon missing, generating ...")
        subprocess.run([sys.executable, "make_icon.py"], cwd=HERE, check=True)
    return ICON


def write_version_files() -> tuple[pathlib.Path, pathlib.Path]:
    gui_v = BUILD / "version_gui.txt"
    mcp_v = BUILD / "version_mcp.txt"
    BUILD.mkdir(exist_ok=True)
    gui_v.write_text(VERSION_INFO, encoding="utf-8")
    mcp_v.write_text(VERSION_INFO_MCP, encoding="utf-8")
    return gui_v, mcp_v


def build(
    script: str,
    name: str,
    *,
    windowed: bool,
    icon: pathlib.Path,
    version_file: pathlib.Path,
    extra_hidden: list[str],
    clean: bool,
    onefile: bool = False,
) -> pathlib.Path:
    import PyInstaller.__main__

    args = [
        str(HERE / script),
        "--name", name,
        "--distpath", str(DIST),
        "--workpath", str(BUILD / name),
        "--specpath", str(BUILD),
        "--icon", str(icon.resolve()),
        "--version-file", str(version_file),
        "--noconfirm",
        "--paths", str(HERE),
        # The icon files must travel inside the bundle.  Without them Tk has
        # no .ico to set and falls back to its own feather in the title bar,
        # even though the PE resource already carries the right icon.
        "--add-data", f"{ICON.parent}{os.pathsep}assets",
        # the certificate store reads files next to the exe; bundle nothing
        # that would go stale, only the code and its imports
        "--exclude-module", "tkinter.test",
        "--exclude-module", "test",
        "--exclude-module", "unittest",
        "--exclude-module", "pydoc_data",
        "--exclude-module", "numpy",
        "--exclude-module", "pandas",
        "--exclude-module", "matplotlib",
        "--exclude-module", "PIL.ImageQt",
        "--exclude-module", "PIL.ImageTk",
    ]
    args.append("--onefile" if onefile else "--onedir")
    if windowed:
        args.append("--windowed")
    else:
        args.append("--console")
    for mod in extra_hidden:
        args += ["--hidden-import", mod]
    if clean:
        args.append("--clean")

    print(f"\n[build] {name}  (windowed={windowed}, onefile={onefile})")
    PyInstaller.__main__.run(args)

    exe = DIST / name / f"{name}.exe" if not onefile else DIST / f"{name}.exe"
    if not exe.exists():
        raise SystemExit(f"build failed: {exe} not produced")
    return exe


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Windows executables")
    ap.add_argument("--only", choices=["gui", "mcp"], default=None)
    ap.add_argument("--no-clean", action="store_true")
    ap.add_argument("--keep-build", action="store_true")
    ap.add_argument(
        "--onefile",
        action="store_true",
        help="single-file exe (self-extracts to %%TEMP%% on every run; slower "
        "startup and blocked by some sandboxes - onedir is the default)",
    )
    ap.add_argument(
        "--standalone-mcp",
        action="store_true",
        help="also build the separate MCP-only exe (the GUI already hosts MCP)",
    )
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    icon = ensure_icon()
    gui_version, mcp_version = write_version_files()
    clean = not args.no_clean

    t0 = time.time()
    made: list[pathlib.Path] = []

    if args.only in (None, "gui"):
        made.append(
            build(
                "cert_manager.py",
                "NixGCCertManager",
                windowed=True,
                icon=icon,
                version_file=gui_version,
                extra_hidden=[
                    "certstore",
                    "mcp_server",
                    "mcp",
                    "mcp.server.mcpserver",
                    "uvicorn",
                    "starlette",
                    "anyio",
                    "sse_starlette",
                    "cryptography.hazmat.bindings._rust",
                ],
                clean=clean,
                onefile=args.onefile,
            )
        )

    # The GUI hosts the MCP server in-process, so this second exe is optional:
    # only build it when someone explicitly wants a headless MCP binary.
    if args.standalone_mcp:
        made.append(
            build(
                "nixgc_cert_mcp.py",
                "nixgc-cert-mcp",
                windowed=False,
                icon=icon,
                version_file=mcp_version,
                extra_hidden=[
                    "certstore",
                    "mcp_server",
                    "mcp",
                    "mcp.server.mcpserver",
                    "uvicorn",
                    "starlette",
                    "anyio",
                    "sse_starlette",
                    "cryptography.hazmat.bindings._rust",
                ],
                clean=clean,
                onefile=args.onefile,
            )
        )

    print("\n" + "=" * 62)
    for p in made:
        mb = p.stat().st_size / (1024 * 1024)
        print(f"  {p}  ({mb:.1f} MB)")
    print(f"  elapsed {time.time() - t0:.1f}s")
    print("=" * 62)

    if not args.keep_build:
        shutil.rmtree(BUILD, ignore_errors=True)
        print("  cleaned build/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


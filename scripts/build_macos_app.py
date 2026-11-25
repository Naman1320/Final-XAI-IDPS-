"""Build the local macOS dashboard client using Apple's command-line tools."""

import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "soc/web"
SOURCE = ROOT / "soc/macos"
OUTPUT = ROOT / "dist/macos/IDPS SOC.app"
BUNDLE_ID = "org.idps.soc.dashboard"


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def swift_flags(stage):
    # Some upgraded Command Line Tools installations retain two declarations
    # of SwiftBridging. Hide the redundant old map only for this compiler run.
    swiftc = Path(subprocess.check_output(["xcrun", "--find", "swiftc"], text=True).strip())
    include = swiftc.parent.parent / "include/swift"
    old, new = include / "module.modulemap", include / "bridging.modulemap"
    def declarations(path):
        return [s.strip() for s in path.read_text().splitlines() if s.strip() and not s.lstrip().startswith("//")]
    if old.is_file() and new.is_file() and declarations(old) == declarations(new):
        empty = stage / "empty.modulemap"
        empty.touch()
        overlay = stage / "toolchain-overlay.json"
        overlay.write_text(json.dumps({"version": 0, "roots": [
            {"type": "file", "name": str(old), "external-contents": str(empty)}]}))
        return ["-vfsoverlay", str(overlay), "-Xcc", "-ivfsoverlay", "-Xcc", str(overlay)]
    return []


def main():
    if sys.platform != "darwin":
        sys.exit("Build the application on macOS.")
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        sys.exit("Build with the project's Node and npm on PATH.")
    run(npm, "run", "build:unified", cwd=WEB)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT.exists():
        with (OUTPUT / "Contents/Info.plist").open("rb") as file:
            if plistlib.load(file).get("CFBundleIdentifier") != BUNDLE_ID:
                sys.exit(f"Another application occupies {OUTPUT}")
    with tempfile.TemporaryDirectory(dir=OUTPUT.parent) as staging:
        stage = Path(staging)
        bundle = stage / OUTPUT.name
        contents = bundle / "Contents"
        executable = contents / "MacOS/IDPSSOC"
        resources = contents / "Resources"
        executable.parent.mkdir(parents=True)
        resources.mkdir()
        shutil.copytree(WEB / "dist-unified", resources / "Dashboard")
        run("xcrun", "swiftc", "-parse-as-library", "-O", "-target", f"{platform.machine()}-apple-macos13.0",
            "-module-cache-path", str(ROOT / "build/macos-modules"), *swift_flags(stage), *sorted(SOURCE.glob("*.swift")),
            "-o", executable)
        iconset = stage / "Dashboard.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                pixels = str(size * scale)
                suffix = "@2x" if scale == 2 else ""
                run("sips", "-s", "format", "png", "-z", pixels, pixels, SOURCE / "AppIcon.svg",
                    "--out", iconset / f"icon_{size}x{size}{suffix}.png", stdout=subprocess.DEVNULL)
        run("iconutil", "-c", "icns", iconset, "-o", resources / "Dashboard.icns")
        with (contents / "Info.plist").open("wb") as file:
            plistlib.dump({
                "CFBundleIdentifier": BUNDLE_ID, "CFBundleName": "IDPS SOC",
                "CFBundleDisplayName": "IDPS SOC", "CFBundleExecutable": executable.name,
                "CFBundleIconFile": "Dashboard.icns", "CFBundlePackageType": "APPL",
                "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
                "LSMinimumSystemVersion": "13.0", "NSHighResolutionCapable": True,
                "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
                "IDPSWebRoot": str(WEB), "IDPSNode": os.path.abspath(node),
            }, file)
        run("codesign", "--force", "--sign", "-", bundle)
        run("codesign", "--verify", "--strict", bundle)
        previous = stage / "previous.app"
        if OUTPUT.exists():
            OUTPUT.rename(previous)
        try:
            bundle.rename(OUTPUT)
        except OSError:
            if previous.exists():
                previous.rename(OUTPUT)
            raise
    print(OUTPUT)


if __name__ == "__main__":
    main()

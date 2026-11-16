"""Checks a Prusa Connect extension release directory, writes its checksums and
packs it into the .tar.gz the Prusa Plugin Marketplace takes.

The checks are the marketplace's deterministic gates (archive, manifest and
layout policy), run here first so an author learns about a broken release in
their own workflow instead of in the review queue. The marketplace runs them
again; nothing here replaces that.

Standard library only: it runs on any GitHub-hosted runner as `python3 -I`.

    python3 -I release.py inspect  <release-dir>             -> JSON facts on stdout
    python3 -I release.py checksum <release-dir>             -> writes checksums.txt
    python3 -I release.py pack     <release-dir> <out.tar.gz>
    python3 -I release.py namespace <module-path>            -> extension id on stdout
"""

import gzip
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import tarfile
import unicodedata

MANIFEST = "module.yaml"
CHECKSUMS = "checksums.txt"
SIGNATURE = "checksums.txt.sig"
ROOT_DOCS = {"LICENSE", "LICENSE.md", "LICENSE.txt", "README.md", "CHANGELOG.md"}
UI_EXTENSIONS = {
    ".js", ".mjs", ".css", ".json", ".map", ".svg", ".png", ".jpg", ".jpeg",
    ".webp", ".woff", ".woff2",
}
GOOS = {"linux": "elf", "freebsd": "elf", "darwin": "macho", "windows": "pe"}
GOARCH = {"amd64", "arm64", "arm", "386", "riscv64"}
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
MAX_FILES = 4096
MAX_PATH_BYTES = 255
MAX_ARCHIVE = 45 * 1024 * 1024  # what the publish endpoint takes, decoded

ELF_MACHINES = {0x03: "386", 0x28: "arm", 0x3E: "amd64", 0xB7: "arm64", 0xF3: "riscv64"}
MACHO_CPUS = {0x00000007: "386", 0x01000007: "amd64", 0x0000000C: "arm", 0x0100000C: "arm64"}
PE_MACHINES = {0x014C: "386", 0x8664: "amd64", 0xAA64: "arm64", 0x01C4: "arm"}

PRIVATE_KEY = re.compile(rb"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----")


class Refused(Exception):
    pass


def refuse(message):
    raise Refused(message)


# ── module.yaml ──────────────────────────────────────────────────────
# The few keys the release layout depends on, read without a YAML library.
# Prusa Connect and the marketplace read the whole manifest; this only has to
# agree with them on name, version, contract_major, platforms and ui.entry.

def _scalar(text):
    text = re.sub(r"\s+#.*$", "", text).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return text


def read_manifest(path):
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except UnicodeDecodeError:
        refuse("module.yaml is not UTF-8")
    top, platforms, ui = {}, [], None
    block = None
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] not in " \t-":
            key, _, value = line.partition(":")
            key = key.strip()
            block = key
            if value.strip():
                top[key] = _scalar(value)
            if key == "ui":
                ui = {}
            continue
        stripped = line.strip()
        if block == "platforms" and stripped.startswith("- "):
            platforms.append(_scalar(stripped[2:]))
        elif block == "ui" and ui is not None and re.match(r"^[ \t]{1,4}entry:", line):
            ui["entry"] = _scalar(stripped.partition(":")[2])
    return {
        "name": top.get("name", ""),
        "version": top.get("version", ""),
        "license": top.get("license", ""),
        "contract_major": int(top["contract_major"]) if top.get("contract_major", "").isdigit() else 0,
        "platforms": platforms,
        "ui_entry": (ui or {}).get("entry"),
        "has_ui": ui is not None,
    }


# ── binaries ─────────────────────────────────────────────────────────

def identify(data):
    """(format, goarch) from an executable header, or None."""
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        little = data[5] == 1
        machine = struct.unpack("<H" if little else ">H", data[18:20])[0]
        return "elf", ELF_MACHINES.get(machine)
    if len(data) >= 8:
        magic = struct.unpack(">I", data[:4])[0]
        if magic in (0xCFFAEDFE, 0xCEFAEDFE):  # little-endian Mach-O
            return "macho", MACHO_CPUS.get(struct.unpack("<I", data[4:8])[0])
        if magic in (0xFEEDFACF, 0xFEEDFACE):
            return "macho", MACHO_CPUS.get(struct.unpack(">I", data[4:8])[0])
        if magic == 0xCAFEBABE:  # universal: not one platform
            return "macho-universal", None
    if data[:2] == b"MZ" and len(data) >= 0x40:
        offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[offset:offset + 4] == b"PE\0\0" and len(data) >= offset + 6:
            return "pe", PE_MACHINES.get(struct.unpack("<H", data[offset + 4:offset + 6])[0])
    return None


def binary_name(name, platform):
    return f"{name}_{platform}" + (".exe" if platform.startswith("windows_") else "")


# ── the release ──────────────────────────────────────────────────────

def walk(release):
    """Every regular file under release, as sorted relative paths. Refuses what
    the marketplace's archive policy refuses."""
    files = []
    for top, dirs, names in os.walk(release):
        dirs.sort()
        for entry in dirs + names:
            full = os.path.join(top, entry)
            relative = os.path.relpath(full, release).replace(os.sep, "/")
            if entry.startswith("."):
                refuse(f"{relative}: hidden files are not allowed in a release")
            if unicodedata.normalize("NFC", relative) != relative or not relative.isprintable():
                refuse(f"{relative!r}: file names must be printable NFC text")
            if len(relative.encode()) > MAX_PATH_BYTES:
                refuse(f"{relative[:64]}...: paths are at most {MAX_PATH_BYTES} bytes")
            mode = os.lstat(full).st_mode
            if stat.S_ISLNK(mode):
                refuse(f"{relative}: symbolic links are not allowed in a release")
            if stat.S_ISREG(mode):
                files.append(relative)
            elif not stat.S_ISDIR(mode):
                refuse(f"{relative}: only regular files and directories are allowed")
    if len(files) > MAX_FILES:
        refuse(f"the release has {len(files)} files, at most {MAX_FILES} are allowed")
    return sorted(files, key=lambda path: path.encode())


def inspect(release):
    if not os.path.isfile(os.path.join(release, MANIFEST)):
        refuse(f"{release} has no {MANIFEST}. Point the path input at the built release directory")
    manifest = read_manifest(os.path.join(release, MANIFEST))
    name, version = manifest["name"], manifest["version"]
    if not NAME.match(name):
        refuse(f"module.yaml name must be lowercase letters, digits and hyphens (got {name!r})")
    if not SEMVER.match(version):
        refuse(f"module.yaml version must be an exact semantic version, e.g. 1.2.0 (got {version!r})")
    license = manifest["license"].strip()
    if not license:
        refuse("module.yaml has no license: state the licence the extension is under, e.g. license: MIT")
    if len(license) > 200:
        refuse(f"module.yaml license is {len(license)} characters, at most 200 are allowed")

    files = walk(release)
    binaries = {}
    problems = []
    for platform in manifest["platforms"]:
        goos, _, goarch = platform.partition("_")
        if goos not in GOOS or goarch not in GOARCH:
            problems.append(f"platform {platform!r} is not a GOOS_GOARCH Prusa Connect is built for")
            continue
        path = binary_name(name, platform)
        full = os.path.join(release, path)
        if not os.path.isfile(full):
            problems.append(f"{platform} is declared in module.yaml but {path} is not in the release")
            continue
        with open(full, "rb") as handle:
            header = handle.read(4096)
        identity = identify(header)
        if identity is None:
            problems.append(f"{path} is not an ELF, Mach-O or PE executable")
        elif identity != (GOOS[goos], goarch):
            problems.append(f"{path}: the header says {identity[0]}/{identity[1]}, the name says {platform}")
        binaries[path] = platform
    if manifest["contract_major"] > 0 and not manifest["platforms"]:
        problems.append("contract_major names a process half, but module.yaml declares no platforms")
    if manifest["has_ui"]:
        entry = (manifest["ui_entry"] or "").removeprefix("./")
        if not entry or entry not in files:
            problems.append(f"ui.entry names {entry or 'nothing'}, which is not in the release")
    elif any(path.startswith("ui/") for path in files):
        problems.append("the release carries ui/ files but module.yaml declares no ui block")
    if not manifest["has_ui"] and not manifest["platforms"]:
        problems.append("module.yaml declares neither a process (platforms) nor a browser bundle (ui)")

    for path in files:
        if path in (MANIFEST, CHECKSUMS, SIGNATURE) or path in binaries:
            continue
        if "/" not in path and path in ROOT_DOCS:
            continue
        if path.startswith("ui/") and os.path.splitext(path)[1].lower() in UI_EXTENSIONS:
            full = os.path.join(release, path)
            if os.stat(full).st_mode & 0o111:
                problems.append(f"{path}: nothing under ui/ may be executable")
            continue
        problems.append(
            f"{path}: only module.yaml, the platform binaries, ui/ (scripts, styles, JSON, images, fonts) "
            "and LICENSE/README.md/CHANGELOG.md are allowed in a release"
        )

    for path in files:
        if path in binaries:
            continue
        with open(os.path.join(release, path), "rb") as handle:
            data = handle.read()
        if PRIVATE_KEY.search(data):
            problems.append(f"{path} contains a private key, which would be published with the release")
        if path.endswith(".json") or path == MANIFEST:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                problems.append(f"{path} is not UTF-8")
                continue
            if path.endswith(".json"):
                try:
                    json.loads(text)
                except ValueError as error:
                    problems.append(f"{path} is not valid JSON: {error}")

    if problems:
        refuse("the release would be refused by the marketplace:\n  - " + "\n  - ".join(problems))
    return {
        "name": name,
        "version": version,
        "platforms": sorted(binaries.values()),
        "binaries": sorted(binaries),
        "ui": manifest["has_ui"],
        "files": [path for path in files if path not in (CHECKSUMS, SIGNATURE)],
    }


def checksum(release):
    facts = inspect(release)
    lines = []
    for path in facts["files"]:
        digest = hashlib.sha256()
        with open(os.path.join(release, path), "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  {path}\n")
    with open(os.path.join(release, CHECKSUMS), "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(lines)
    return facts


def pack(release, out):
    """A deterministic archive: regular files only, sorted, owner 0, time 0,
    binaries 755 and the rest 644. Python's tarfile writes the same bytes on
    Linux and macOS, where GNU and BSD tar differ."""
    facts = inspect(release)
    if not os.path.isfile(os.path.join(release, SIGNATURE)):
        refuse(f"{SIGNATURE} is missing; sign {CHECKSUMS} first")
    binaries = set(facts["binaries"])
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(facts["files"] + [CHECKSUMS, SIGNATURE], key=lambda p: p.encode()):
            with open(os.path.join(release, path), "rb") as handle:
                data = handle.read()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = 0o755 if path in binaries else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, compresslevel=9, mtime=0) as packed:
            packed.write(buffer.getvalue())
    size = os.path.getsize(out)
    if size > MAX_ARCHIVE:
        refuse(f"the archive is {size} bytes and the publish endpoint takes at most {MAX_ARCHIVE}")
    return {**facts, "archive": out, "size": size}


# ── the extension id ─────────────────────────────────────────────────
# Prusa Connect's NamespaceOf, as the marketplace ports it: the reversed host,
# "aux", then the rest of the path. github.com/acme/spools -> com.github.aux.acme.spools

DNS_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def namespace(module):
    segments = module.split("/")
    if len(segments) > 1 and re.fullmatch(r"v[0-9]+", segments[-1]):
        segments.pop()
    host, rest = segments[0].split("."), segments[1:]
    for label in host + rest:
        if not DNS_LABEL.match(label):
            refuse(f"module {module!r}: {label!r} is not a lowercase DNS label (a-z, 0-9, inner '-')")
        if label == "aux":
            refuse(f"module {module!r}: 'aux' is reserved, it marks where the host ends")
    labels = list(reversed(host)) + (["aux"] + rest if rest else [])
    result = ".".join(labels)
    if len(labels) < 2 or result == "core":
        refuse(f"module {module!r} needs a host and a path, as github.com/acme/spools has")
    if len(result) > 96:
        refuse(f"module {module!r} renders as {len(result)} bytes, and the limit is 96")
    return result


def main(argv):
    try:
        command, args = argv[1], argv[2:]
        if command == "inspect" and len(args) == 1:
            print(json.dumps(inspect(args[0])))
        elif command == "checksum" and len(args) == 1:
            print(json.dumps(checksum(args[0])))
        elif command == "pack" and len(args) == 2:
            print(json.dumps(pack(args[0], args[1])))
        elif command == "namespace" and len(args) == 1:
            print(namespace(args[0]))
        else:
            sys.exit(__doc__)
    except Refused as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)

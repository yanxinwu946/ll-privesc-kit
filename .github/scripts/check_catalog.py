"""Check the CVE catalog and its local documentation paths."""

import json
import re
from pathlib import Path


def check_catalog(root):
    with (root / "manifest.json").open(encoding="utf-8") as manifest:
        entries = json.load(manifest)["exploits"]

    if not isinstance(entries, list) or not entries:
        raise ValueError("'exploits' must be a non-empty list")

    directory_ids = set()
    cve_ids = set()
    for entry in entries:
        directory_id = entry["id"]
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", directory_id):
            raise ValueError(f"Invalid directory ID: {directory_id!r}")
        if directory_id in directory_ids:
            raise ValueError(f"Duplicate directory ID: {directory_id}")
        directory_ids.add(directory_id)

        readme = root / directory_id / "README.md"
        if not readme.is_file():
            raise ValueError(f"Missing documentation: {readme.relative_to(root)}")

        for value in entry["cve"].split("/"):
            cve_id = value.strip()
            if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve_id):
                raise ValueError(f"{directory_id}: invalid CVE ID {cve_id!r}")
            if cve_id in cve_ids:
                raise ValueError(f"{directory_id}: duplicate CVE ID {cve_id}")
            cve_ids.add(cve_id)

    print(f"Checked {len(directory_ids)} catalog entries and {len(cve_ids)} CVE IDs.")


if __name__ == "__main__":
    try:
        check_catalog(Path(__file__).resolve().parents[2])
    except (OSError, KeyError, TypeError, AttributeError, ValueError) as error:
        raise SystemExit(f"manifest.json: {error}") from error

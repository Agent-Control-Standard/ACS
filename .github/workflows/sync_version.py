#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The OWASP GenAI Security Project and the ACS contributors
"""
Script to synchronize version from version.txt to all project files.
"""
# /// script
# dependencies = ["toml"]
# ///

import os
import re
import json
import sys
import toml


def main():
    """Sync version from command line argument to all project files."""
    if len(sys.argv) != 2:
        print("Usage: sync_version.py <version>")
        sys.exit(1)
    
    version = sys.argv[1]
    
    # Update pyproject.toml
    with open('pyproject.toml', 'r') as f:
        data = toml.load(f)
    data['project']['version'] = version
    with open('pyproject.toml', 'w') as f:
        toml.dump(data, f)
    print(f"✓ Updated pyproject.toml to version {version}")
    
    # Update specification.md
    with open('docs/spec/instrument/specification.md', 'r') as f:
        content = f.read()
    # Replace **Version:** `x.y.z` pattern
    updated_content = re.sub(
        r'\*\*Version:\*\*\s*`[^`]+`',
        f'**Version:** `{version}`',
        content
    )
    with open('docs/spec/instrument/specification.md', 'w') as f:
        f.write(updated_content)
    print(f"✓ Updated specification.md to version {version}")
    
    # Update acs_schema.json
    with open('specification/ACS/acs_schema.json', 'r') as f:
        data = json.load(f)
    data['version'] = version
    with open('specification/ACS/acs_schema.json', 'w') as f:
        json.dump(data, f, indent=4)
    print(f"✓ Updated acs_schema.json to version {version}")


if __name__ == "__main__":
    main()
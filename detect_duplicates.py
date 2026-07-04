import os
import hashlib
import json
import argparse
from pathlib import Path

def file_hash(path, block_size=8192):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def find_duplicates(root_path):
    hash_map = {}
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Skip version control and node_modules directories
        dirnames[:] = [d for d in dirnames if d not in {'.git', 'node_modules', '__pycache__'}]
        for filename in filenames:
            file_path = Path(dirpath) / filename
            # Skip the duplicate report itself if it exists
            if file_path.name == 'duplicates.json':
                continue
            try:
                h = file_hash(file_path)
            except Exception:
                continue
            hash_map.setdefault(h, []).append(str(file_path))
    # Keep only entries with more than one file
    duplicates = {h: paths for h, paths in hash_map.items() if len(paths) > 1}
    return duplicates

def main():
    parser = argparse.ArgumentParser(description='Detect duplicate files by content hash')
    parser.add_argument('root', nargs='?', default='.', help='Root directory to scan')
    parser.add_argument('--output', default='duplicates.json', help='File to write duplicate report')
    args = parser.parse_args()
    dupes = find_duplicates(args.root)
    output_path = Path(args.root) / args.output
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(dupes, f, indent=2)
    print(f"Found {len(dupes)} sets of duplicate files. Report written to {output_path}")

if __name__ == "__main__":
    main()

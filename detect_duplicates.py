import os, hashlib, json

def file_hash(path, chunk_size=8192):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()

def find_duplicates(root):
    hash_map = {}
    dupes = {}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            filepath = os.path.join(dirpath, name)
            if not os.path.isfile(filepath):
                continue
            try:
                h = file_hash(filepath)
            except Exception:
                continue
            if h in hash_map:
                dupes.setdefault(h, []).append(filepath)
            else:
                hash_map[h] = filepath
    # Include the original file in each list
    for h, paths in dupes.items():
        dupes[h] = [hash_map[h]] + paths
    return dupes

if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser(description='Detect duplicate files by content hash')
    parser.add_argument('root', nargs='?', default='.', help='Root directory to scan')
    parser.add_argument('--output', default='duplicates.json', help='File to write duplicate report')
    args = parser.parse_args()
    dupes = find_duplicates(args.root)
    with open(args.output, 'w') as out:
        json.dump(dupes, out, indent=2)
    print(f'Found {len(dupes)} sets of duplicates. Report written to {args.output}')

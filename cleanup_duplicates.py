import json
import os
import subprocess
from pathlib import Path

DUPLICATES_FILE = 'duplicates.json'

def load_duplicates(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def delete_duplicates(dupes):
    deleted = []
    for hash_val, files in dupes.items():
        # keep the first file, delete the rest
        for file_path in files[1:]:
            try:
                os.remove(file_path)
                deleted.append(file_path)
                print(f"Deleted duplicate: {file_path}")
            except Exception as e:
                print(f"Failed to delete {file_path}: {e}")
    return deleted

def git_commit_and_push(message='Remove duplicate files'):
    # Stage deletions
    subprocess.run(['git', 'add', '-u'], check=True)
    # Commit
    subprocess.run(['git', 'commit', '-m', message], check=True)
    # Push
    subprocess.run(['git', 'push'], check=True)

def main():
    root = Path(__file__).parent
    dupes_path = root / DUPLICATES_FILE
    if not dupes_path.is_file():
        print(f"Duplicate report {dupes_path} not found. Run detect_duplicates.py first.")
        return
    dupes = load_duplicates(dupes_path)
    if not dupes:
        print("No duplicates to remove.")
        return
    deleted = delete_duplicates(dupes)
    if deleted:
        print(f"Deleted {len(deleted)} duplicate files.")
        git_commit_and_push()
        print("Changes pushed to remote.")
    else:
        print("No files were deleted.")

if __name__ == '__main__':
    main()

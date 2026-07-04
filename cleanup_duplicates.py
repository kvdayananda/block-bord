import os, json, subprocess, sys

def load_duplicates(path):
    with open(path, 'r') as f:
        return json.load(f)

def delete_duplicates(dupes, dry_run=False):
    deleted = []
    for hash_val, files in dupes.items():
        # keep the first file, delete the rest
        for dup_path in files[1:]:
            try:
                if dry_run:
                    print(f'[DRY-RUN] Would delete: {dup_path}')
                else:
                    os.remove(dup_path)
                    print(f'Deleted: {dup_path}')
                    deleted.append(dup_path)
            except OSError as e:
                print(f'Error deleting {dup_path}: {e}', file=sys.stderr)
    return deleted

def git_stage_and_commit(deleted_files, commit_msg='Remove duplicate files'):
    if not deleted_files:
        print('No files deleted, nothing to commit.')
        return
    # Stage deletions
    subprocess.run(['git', 'add', '-u'], check=True)
    # Commit
    subprocess.run(['git', 'commit', '-m', commit_msg], check=True)
    print('Committed deletions.')

def git_push():
    subprocess.run(['git', 'push'], check=True)
    print('Pushed to remote.')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Delete duplicate files and push changes to git')
    parser.add_argument('dup_json', help='Path to duplicates JSON file produced by detect_duplicates.py')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted without removing files')
    parser.add_argument('--commit-msg', default='Remove duplicate files', help='Commit message for the cleanup')
    args = parser.parse_args()
    dupes = load_duplicates(args.dup_json)
    deleted = delete_duplicates(dupes, dry_run=args.dry_run)
    if not args.dry_run:
        git_stage_and_commit(deleted, args.commit_msg)
        git_push()

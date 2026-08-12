import os
import sys
import shutil
import sqlite3

def restore_database(backup_path=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_db = os.path.join(base_dir, "marketplace.db")
    
    if not backup_path:
        default_backup = os.path.join(base_dir, "original database", "marketplace (1).db")
        if os.path.exists(default_backup):
            backup_path = default_backup
        else:
            print("[ERROR] Please provide a valid backup .db file path.")
            print("Usage: python restore_backup.py <path_to_backup.db>")
            return

    if not os.path.exists(backup_path):
        print(f"[ERROR] Backup file not found at '{backup_path}'")
        return

    print(f"[RESTORE] Starting restoration from: {backup_path}")

    wal_file = os.path.join(base_dir, "marketplace.db-wal")
    shm_file = os.path.join(base_dir, "marketplace.db-shm")
    temp_file = os.path.join(base_dir, "marketplace.db.temp")

    for extra_file in [wal_file, shm_file, temp_file]:
        if os.path.exists(extra_file):
            try:
                os.remove(extra_file)
                print(f"[CLEANUP] Removed old lock file: {os.path.basename(extra_file)}")
            except Exception as e:
                print(f"[WARNING] Could not remove {os.path.basename(extra_file)}. Make sure Flask server is stopped!")
                print(f"          Error details: {e}")

    try:
        shutil.copy2(backup_path, target_db)
        print(f"[SUCCESS] Restored database to '{target_db}'!")
    except PermissionError:
        print("\n[ERROR] Permission Error: 'marketplace.db' is locked by another program.")
        print("SOLUTION: Close the terminal running Flask/app.py or stop run.bat first, then try again.")
        return
    except Exception as e:
        print(f"[ERROR] Failed to restore database: {e}")
        return

    try:
        conn = sqlite3.connect(target_db)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(f"\n[VERIFY] Verified Restored Data ({len(tables)} tables):")
        for t in sorted(tables):
            if not t.startswith("products_fts") and t != "sqlite_sequence":
                count = cur.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]
                print(f"   • {t}: {count} records")
        conn.close()
        print("\n[COMPLETE] Database restore completed successfully! You can now start the app.")
    except Exception as e:
        print(f"[WARNING] Database restore check warning: {e}")

if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else None
    restore_database(src)

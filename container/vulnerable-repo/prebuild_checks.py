import sys
import os
import subprocess
import argparse

# Define the expected Python files
VULNERABLE_PY = "app_vulnerable.py"
FIXED_PY = "app_fixed.py"

def run_bandit(py_file):
    """Executes the Bandit security scanner on the specified Python file."""
    print(f"\n[SCAN] Running Bandit on {py_file}...")
    
    try:
        # Simplified Bandit command: -r recursive, -f screen for output.
        # Bandit returns non-zero (1) if it finds *any* issue.
        result = subprocess.run(
            [sys.executable, '-m', 'bandit', '-r', py_file, '-f', 'screen'],
            capture_output=True, text=True, check=False
        )
        
        print(f"[DEBUG] Bandit Process Return Code: {result.returncode}")
        print("\n--- BANDIT OUTPUT START ---")
        print(result.stdout)
        print("--- BANDIT OUTPUT END ---")
        
        # Bandit returns non-zero if it finds any issue.
        if result.returncode != 0:
            print(f"[STATUS] BANDIT FAILED ({result.returncode}) - Issues found.")
            return True # Indicates failure
        else:
            print("[STATUS] BANDIT PASSED - No issues found.")
            return False # Indicates success

    except FileNotFoundError:
        print("Error: Bandit command not found. Ensure 'bandit' is installed.")
        return True

def run_secret_grep(secret_file):
    """Performs a basic secret-grep check by searching file content."""
    
    print(f"\n[SCAN] Running Secret Grep on {secret_file}...")
    
    # Updated secret patterns for higher reliability
    secret_patterns = ['rsa private key', 'database password', 'access_key']
    failure = False
    
    if os.path.exists(secret_file):
        with open(secret_file, 'r') as f:
            content = f.read().lower()
            for pattern in secret_patterns:
                if pattern in content:
                    print(f"[STATUS] SECRET-GREP FAILED - Found pattern: '{pattern}'")
                    failure = True
                    break
        
        if not failure:
            print("[STATUS] SECRET-GREP PASSED - No obvious patterns found.")
    else:
        print(f"Error: Secret file {secret_file} not found or is missing from Docker context.")
        # We fail if the expected file isn't there, preventing bypass
        failure = True 
        
    return failure

def main():
    parser = argparse.ArgumentParser(description="Run security checks on code.")
    parser.add_argument('file_type', choices=['vulnerable', 'fixed'], help="Specify which code version to check.")
    args = parser.parse_args()

    # Configuration based on file type
    if args.file_type == 'vulnerable':
        py_file = VULNERABLE_PY
        secret_file = "secrets_vuln.txt"
    else:
        py_file = FIXED_PY
        secret_file = "secrets_safe.txt"

    print(f"\n=======================================================")
    print(f"Starting Security Gate Check for {args.file_type.upper()} code.")
    print(f"Target Python File: {py_file}")
    print(f"Target Secret File: {secret_file}")
    print(f"=======================================================")

    # Run checks
    bandit_failed = run_bandit(py_file)
    grep_failed = run_secret_grep(secret_file)
    
    final_failure = bandit_failed or grep_failed

    print("\n-------------------------------------------------------")
    print(f"[DEBUG] Final Bandit Fail Status: {bandit_failed}")
    print(f"[DEBUG] Final Grep Fail Status: {grep_failed}")
    
    if final_failure:
        print("BUILD FAILED: Security checks did not pass.")
        sys.exit(1) # Fail the build
    else:
        print("BUILD PASSED: Security checks completed successfully.")
        sys.exit(0) # Pass the build

if __name__ == '__main__':
    main()

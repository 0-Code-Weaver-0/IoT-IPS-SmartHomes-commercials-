#!/usr/bin/env python3
"""One command that runs every unit test:  python run_tests.py

Looks in this folder and in sibling folders named like person3..person7 (any spelling),
runs each test_*.py in its own folder (so each module finds its own files), and prints one total.
Exit code 0 only if every test file passes.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def folders():
    parent = os.path.dirname(HERE)
    found = [HERE]
    for name in sorted(os.listdir(parent)):
        full = os.path.join(parent, name)
        if full != HERE and os.path.isdir(full) and re.fullmatch(r"person[1-7]", re.sub(r"[^a-z0-9]", "", name.lower())):
            found.append(full)
    return found


def main() -> int:
    failures, total = [], 0
    for folder in folders():
        for name in sorted(os.listdir(folder)):
            if re.fullmatch(r"test_[A-Za-z0-9_]+\.py", name):
                proc = subprocess.run([sys.executable, name], cwd=folder, capture_output=True, text=True, timeout=600)
                tail = (proc.stderr or proc.stdout).strip().splitlines()
                ran = re.search(r"Ran (\d+) test", proc.stderr + proc.stdout)
                count = int(ran.group(1)) if ran else 0
                total += count
                ok = proc.returncode == 0
                print("%-4s %-40s %3d tests" % ("OK" if ok else "FAIL", os.path.basename(folder) + "/" + name, count))
                if not ok:
                    failures.append(name)
                    print("\n".join("     " + line for line in tail[-15:]))
    print("\n%d tests in total, %s" % (total, "ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())

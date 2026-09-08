"""Launch the compiled application without entering any account credentials."""
import subprocess
import sys
import time

process = subprocess.Popen([sys.argv[1]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    time.sleep(8)
    if process.poll() is not None:
        output = process.communicate()[0].decode(errors="replace")
        raise SystemExit("Desktop exited during startup: " + output[-2000:])
    print("Desktop application started and remained running.")
finally:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

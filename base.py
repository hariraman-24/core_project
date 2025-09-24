import time
import csv
from collections import deque

# For colored output in console
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Install colorama for colored output: pip install colorama")
    class Dummy: RESET_ALL = RED = GREEN = YELLOW = CYAN = ""
    Fore = Style = Dummy()

# Parameters
THRESHOLD = 3        # number of failures allowed
WINDOW = 60          # seconds (sliding window)
LOG_FILE = "login_logs.csv"

# DFA states
class DFA:
    def __init__(self):
        self.state = "S0"
        self.failures = deque()

    def process_attempt(self, username, ip, success):
        now = time.time()

        # Clean old failures outside the time window
        while self.failures and now - self.failures[0] > WINDOW:
            self.failures.popleft()

        if success:
            self.state = "S0"
            self.failures.clear()
            result = "SUCCESS"
            self._print_state(ip, username, result, Fore.GREEN)
        else:
            self.failures.append(now)
            if len(self.failures) >= THRESHOLD:
                self.state = "BLOCKED"
                result = "BLOCKED"
                self._print_state(ip, username, result, Fore.RED)
            else:
                self.state = f"S{len(self.failures)}"
                result = "FAILED"
                self._print_state(ip, username, result, Fore.YELLOW)

        # Log attempt
        self.log_attempt(username, ip, result)

        return self.state

    def _print_state(self, ip, username, result, color):
        print(color + f"[{time.strftime('%H:%M:%S')}] User: {username}, "
                      f"IP: {ip}, Result: {result}, State: {self.state}" + Style.RESET_ALL)

    def log_attempt(self, username, ip, result):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, username, ip, result, self.state])


# ---------------- DEMO ---------------- #
if __name__ == "__main__":
    dfa = DFA()

    # Simulated login attempts
    attempts = [
        ("alice", "192.168.1.10", False),
        ("alice", "192.168.1.10", False),
        ("alice", "192.168.1.10", False),  # triggers BLOCK
        ("alice", "192.168.1.10", True),   # reset to S0
    ]

    for user, ip, success in attempts:
        dfa.process_attempt(user, ip, success)
        time.sleep(1)  # small delay to simulate real login attempts

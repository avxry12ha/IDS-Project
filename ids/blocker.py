import platform
import subprocess


class Blocker:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def block(self, ip_address: str) -> bool:
        if not self.enabled:
            return False
        if platform.system().lower() != "linux":
            return False
        command = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Failed to block {ip_address}: {result.stderr}")
            return False
        print(f"Blocked {ip_address} via iptables.")
        return True

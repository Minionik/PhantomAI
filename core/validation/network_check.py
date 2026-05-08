import subprocess

class NetworkChecker:
    def ping(self, target):
        try:
            cmd = f"ping -n 2 {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return "TTL=" in result.stdout
        except:
            return False

    def nmap_scan(self, target):
        try:
            cmd = f"nmap -F {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout[:500]
        except:
            return "error"
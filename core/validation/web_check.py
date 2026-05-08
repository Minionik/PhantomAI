import subprocess

class WebChecker:
    def check_http(self, target):
        try:
            cmd = f"curl -I -m 5 http://{target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return any(code in result.stdout for code in ["200", "301", "302"])
        except:
            return False

    def check_https(self, target):
        try:
            cmd = f"curl -I -m 5 https://{target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return any(code in result.stdout for code in ["200", "301", "302"])
        except:
            return False

    def check_httpx(self, target):
        try:
            cmd = f"httpx -silent -u {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return ""
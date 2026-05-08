import subprocess
import shlex


def run_cmd(cmd: str, timeout: int = 60) -> list[str]:
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return [line for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def run_cmd_str(cmd: str, timeout: int = 60) -> str:
    return "\n".join(run_cmd(cmd, timeout))


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        s = item.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out

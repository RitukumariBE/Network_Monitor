import subprocess
import platform
import re
import os

def ping_device(ip):
    system = platform.system()
    ping_count = os.getenv("PING_COUNT", "1")
    ping_timeout_ms = os.getenv("PING_TIMEOUT_MS", "1000")

    # Windows uses -n, Linux uses -c
    if system == "Windows":
        command = ["ping", "-n", ping_count, "-w", ping_timeout_ms, ip]
    else:
        timeout_seconds = str(max(1, int(int(ping_timeout_ms) / 1000)))
        command = ["ping", "-c", ping_count, "-W", timeout_seconds, ip]

    # FIX: subprocess timeout must be strictly greater than ping's own timeout
    # so we give it ping_timeout_ms + 1 second buffer, minimum 3 seconds
    subprocess_timeout = max(3, int(int(ping_timeout_ms) / 1000) + 1)

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=subprocess_timeout   # FIX: was int(ping_count)*2 which was too short
        )

        output = result.stdout.decode('utf-8', errors='ignore')

        if result.returncode == 0:
            # Extract response time from ping output
            if system == "Windows":
                # Windows output: "Average = 23ms"
                match = re.search(r'Average = (\d+)ms', output)
            else:
                # Linux output: "rtt min/avg/max = 1.234/2.345/3.456 ms"
                match = re.search(r'rtt min/avg/max = [\d.]+/([\d.]+)/', output)

            if match:
                response_time = int(float(match.group(1)))
            else:
                response_time = 0

            return "UP", response_time
        else:
            return "DOWN", None

    except subprocess.TimeoutExpired:
        # FIX: handle timeout explicitly — treat as DOWN, not UNKNOWN
        print(f"  ⏱️  Ping timeout for {ip}")
        return "DOWN", None
    except Exception as e:
        print(f"  ❌ Error pinging {ip}: {e}")
        return "UNKNOWN", None


# ── Test it directly ──
if __name__ == "__main__":
    test_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "192.168.1.1",
        "192.168.1.255",
        "10.0.0.99",
    ]

    print("Testing ping engine...\n")
    for ip in test_ips:
        status, response_time = ping_device(ip)
        symbol = "🟢" if status == "UP" else "🔴"
        if response_time is not None:
            print(f"  {symbol} {ip} → {status} ({response_time}ms)")
        else:
            print(f"  {symbol} {ip} → {status}")
import os
import re

patterns = [
    r"adicionar_dispositivo_com_subrede",
    r"obter_ip_local",
    r"detectar_cidr_robusto",
    r"gateway",
    r"descobrir_rede",
    r"limite",
    r"MAX_DISPOSITIVOS"
]

results = {p: [] for p in patterns}

for root, dirs, files in os.walk("."):
    if "venv" in root or ".git" in root or "__pycache__" in root or "build" in root or "dist" in root:
        continue
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, 1):
                        for p in patterns:
                            if re.search(p, line, re.IGNORECASE):
                                results[p].append(f"{path}:{line_num} - {line.strip()}")
            except Exception as e:
                pass

for p, res in results.items():
    print(f"=== Pattern: {p} ===")
    for r in res[:30]:  # Limit output
        print(r)
    if len(res) > 30:
        print(f"... and {len(res) - 30} more")
    print()

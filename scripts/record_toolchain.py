"""Record installed tool versions without inventing deployment evidence."""
import importlib.metadata
from pathlib import Path

names = ["genlayer-py", "genlayer-test", "genvm-linter", "pytest"]
lines = ["Target network: studionet", "Target chain ID: 61999", "Target RPC: https://studio.genlayer.com/api"]
for name in names:
    try:
        lines.append(f"{name}=={importlib.metadata.version(name)}")
    except importlib.metadata.PackageNotFoundError:
        lines.append(f"{name}==NOT_INSTALLED")
lines.append("python=" + __import__("platform").python_version())
Path("toolchain.lock.txt").write_text("\n".join(lines) + "\n")
print("wrote toolchain.lock.txt")

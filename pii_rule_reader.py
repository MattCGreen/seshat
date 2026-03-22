import yaml
import sys
from pathlib import Path


def load_policy(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text())


def print_policy(policy: dict, indent: int = 0) -> None:
    for key, value in policy.items():
        prefix = "  " * indent
        if isinstance(value, dict):
            print(f"{prefix}{key}:")
            print_policy(value, indent + 1)
        elif isinstance(value, list):
            print(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    print_policy(item, indent + 1)
                else:
                    print(f"{prefix}  - {item}")
        else:
            print(f"{prefix}{key}: {value}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "pii_rule.yml"
    policy = load_policy(path)
    print_policy(policy)
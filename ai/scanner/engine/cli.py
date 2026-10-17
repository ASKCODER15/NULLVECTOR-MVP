"""Command-line interface for the prompt-injection scanner.

Usage:
  python -m ai.scanner.engine.cli "ignore previous instructions"
  python -m ai.scanner.engine.cli --json "text"
  python -m ai.scanner.engine.cli --interactive
  cat input.txt | python -m ai.scanner.engine.cli
"""

import argparse
import json
import sys

from .scanner import RULES_PATH, load_rules, scan


def _print_human(result) -> None:
    bar_len = 30
    filled = int(result.risk_score * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)
    print(f"Risk level : {result.level}")
    print(f"Risk score : {result.risk_score:.3f}  [{bar}]")
    if result.detections:
        print("\nDetections:")
        for d in result.detections:
            print(f"  - {d.match!r}  (weight {d.weight:.2f})  [{d.pattern}]")
    else:
        print("\nNo detections found.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect potential prompt injection in user-provided text.",
    )
    parser.add_argument("text", nargs="?", help="Text to scan (omit to read from stdin)")
    parser.add_argument("--file", help="Read text from a file")
    parser.add_argument("--rules", default=RULES_PATH, help="Path to rules.json config")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive REPL")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Exit with code 1 if risk_score >= threshold (for scripting)",
    )
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)

    def run(text: str, json_output: bool) -> int:
        result = scan(text, rules)
        if json_output:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            _print_human(result)
        if args.threshold is not None and result.risk_score >= args.threshold:
            return 1
        return 0

    if args.interactive:
        print("Prompt injection scanner. Type text, 'q' to quit.")
        while True:
            try:
                line = input("> ")
            except (EOFError, KeyboardInterrupt):
                break
            if line.strip().lower() in ("q", "quit", "exit"):
                break
            run(line, args.json)
        return 0

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            text = fh.read()
    elif args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read()

    return run(text, args.json)


if __name__ == "__main__":
    sys.exit(main())
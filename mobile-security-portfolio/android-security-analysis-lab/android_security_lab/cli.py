
import argparse
import json
import sys
from .analyzer import analyze_apk, write_reports

def main(argv=None):
    parser = argparse.ArgumentParser(prog="android-security-lab", description="Static Android APK manifest review; APKs are never executed.")
    parser.add_argument("apk", help="Path to an APK you own or are authorized to analyze")
    parser.add_argument("-o", "--output", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--json-only", action="store_true", help="Print the complete JSON result")
    args = parser.parse_args(argv)
    try:
        result = analyze_apk(args.apk)
        json_path, md_path = write_reports(result, args.output)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.json_only:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("Android Security Analysis Lab")
        print("=============================")
        print(f"File: {result['input_file']}")
        print(f"Parser: {result['manifest_parser']}")
        print(f"Findings: {result['summary']['finding_count']}")
        for severity, count in result["summary"]["by_severity"].items():
            print(f"  {severity}: {count}")
        print(f"\nJSON report: {json_path}\nMarkdown report: {md_path}")
        print("\nStatic manifest checks only; review report limitations.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

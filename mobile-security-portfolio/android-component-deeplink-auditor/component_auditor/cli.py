
import argparse, json, sys
from .analyzer import analyze_apk, write_reports

def main(argv=None):
    parser = argparse.ArgumentParser(prog="component-deeplink-auditor", description="Static Android component and deep-link review; APKs are never executed.")
    parser.add_argument("apk", help="APK you own or are authorized to analyze")
    parser.add_argument("-o", "--output", default="reports", help="Output directory")
    parser.add_argument("--json-only", action="store_true", help="Print full JSON report")
    args = parser.parse_args(argv)
    try:
        result = analyze_apk(args.apk)
        jp, mp = write_reports(result, args.output)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.json_only:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("Android Component & Deep-Link Security Auditor")
        print("==============================================")
        print(f"APK: {result['input_file']}")
        print(f"Parser: {result['parser']}")
        print(f"Components: {result['summary']['component_count']}")
        print(f"Deep-link declarations: {result['summary']['deep_link_count']}")
        print(f"Findings: {result['summary']['finding_count']}")
        for sev, count in result["summary"]["by_severity"].items():
            print(f"  {sev}: {count}")
        print(f"\nJSON report: {jp}\nMarkdown report: {mp}")
        print("\nStatic review only. Exported components are not automatically vulnerabilities.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

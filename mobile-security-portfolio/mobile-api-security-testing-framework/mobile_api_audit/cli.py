
import argparse, json, sys
from pathlib import Path
from .runner import load_endpoints, run_audit, write_reports

def main(argv=None):
    parser = argparse.ArgumentParser(description="Safe starter framework for mobile API URL/response security review.")
    parser.add_argument("endpoints", help="JSON file containing endpoint objects")
    parser.add_argument("-o", "--output", default="reports", help="Report output directory")
    parser.add_argument("--active", action="store_true", help="Send limited GET/HEAD requests to listed endpoints")
    parser.add_argument("--allow-http", action="store_true", help="Do not flag HTTP as a finding (does not make it encrypted)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between active requests, seconds")
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.delay < 0:
        parser.error("--timeout must be positive and --delay cannot be negative")
    try:
        endpoints = load_endpoints(args.endpoints)
        report = run_audit(endpoints, active=args.active, allow_http=args.allow_http,
                           timeout=args.timeout, delay=args.delay)
        jp, mp = write_reports(report, args.output)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print("Mobile API Security Testing Framework")
    print("=====================================")
    print(f"Mode: {report['mode']}")
    print(f"Endpoints: {report['summary']['endpoint_count']}")
    print(f"Requests performed: {report['summary']['request_count']}")
    print(f"Findings: {report['summary']['finding_count']}")
    for sev, count in report["summary"]["by_severity"].items(): print(f"  {sev}: {count}")
    print(f"\nJSON report: {jp}\nMarkdown report: {mp}")
    if args.active: print("\nActive mode only sends GET/HEAD to listed URLs. Use only with explicit authorization.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

import argparse, json, sys
from .analyzer import analyze_apk, write_reports

def main(argv=None):
    p=argparse.ArgumentParser(description="Static Android manifest/network-security configuration review. Never runs the APK.")
    p.add_argument("apk",help="APK you own or are authorized to assess")
    p.add_argument("-o","--output",default="reports",help="Report output directory")
    p.add_argument("--json-only",action="store_true",help="Print JSON report")
    args=p.parse_args(argv)
    try:
        report=analyze_apk(args.apk)
        jp,mp=write_reports(report,args.output)
    except (ValueError,OSError) as e:
        print(f"Error: {e}",file=sys.stderr); return 2
    if args.json_only: print(json.dumps(report,indent=2,ensure_ascii=False))
    else:
        print("Android Network & TLS Security Analyzer")
        print("=======================================")
        print(f"APK: {report['input_file']}")
        print(f"Package: {report['metadata']['package']}")
        print(f"Findings: {report['summary']['finding_count']}")
        for s,n in report["summary"]["by_severity"].items(): print(f"  {s}: {n}")
        print(f"\\nJSON report: {jp}\\nMarkdown report: {mp}")
        print("\\nStatic analysis only; no app execution or network traffic.")
    return 0
if __name__=="__main__": raise SystemExit(main())

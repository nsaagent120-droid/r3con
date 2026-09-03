"""
r3con - CI Runner
Point d'entrée pour les pipelines CI/CD.
Usage: python -m r3con_ci --target . --format sarif --output results.sarif
"""

import sys
import os
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def main():
    parser = argparse.ArgumentParser(
        description='r3con CI/CD Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m r3con_ci --target ./src --format sarif --output results.sarif
  python -m r3con_ci --target ./app.apk --format json
  python -m r3con_ci --target . --fail-on CRITICAL
  python -m r3con_ci --target . --format all --output ./reports/
        """
    )

    parser.add_argument('--target',   required=True,
                        help='File or directory to analyze')
    parser.add_argument('--format',   default='text',
                        choices=['text','json','sarif','all'],
                        help='Output format (default: text)')
    parser.add_argument('--output',   default=None,
                        help='Output file or directory')
    parser.add_argument('--fail-on',  default=None,
                        choices=['CRITICAL','HIGH','MEDIUM','LOW'],
                        help='Exit code 1 if findings at this level or above')
    parser.add_argument('--scan',     default='all',
                        choices=['all','source','deps','yara'],
                        help='What to scan (default: all)')
    parser.add_argument('--no-cache', action='store_true',
                        help='Disable incremental cache')
    parser.add_argument('--workers',  type=int, default=4,
                        help='Parallel workers (default: 4)')
    parser.add_argument('--quiet',    action='store_true',
                        help='Minimal output')

    args = parser.parse_args()

    # Setup
    os.environ['R3CON_EXPERT_MODE'] = 'true'

    if not args.quiet:
        print("\n\033[36m r3con CI Scanner v4.3.0\033[0m")
        print(f" Target: {args.target}")
        print(f" Format: {args.format}")
        print(f" Scan:   {args.scan}\n")

    # Run pipeline
    from modules.performance.batch_pipeline import BatchPipeline

    pipeline = BatchPipeline(
        expert_mode=True,
        use_cache=not args.no_cache,
        max_workers=args.workers
    )

    result = pipeline.run(
        target=args.target,
        scan_deps=(args.scan in ('all', 'deps')),
        scan_yara=(args.scan in ('all', 'yara')),
        generate_sarif=(args.format in ('sarif', 'all')),
        generate_bounty=False,
    )

    all_findings = result.get('all_findings', [])
    summary      = result.get('summary', {})

    # Output results
    if args.format == 'text' or args.format == 'all':
        _print_text(all_findings, summary, args.quiet)

    if args.format == 'json' or args.format == 'all':
        output = _json_output(all_findings, summary, args)
        if output:
            print(f" JSON: {output}")

    if args.format == 'sarif' or args.format == 'all':
        sarif_out = result.get('outputs', {}).get('sarif')
        if sarif_out and not args.quiet:
            print(f" SARIF: {sarif_out}")

    # Fail on severity
    if args.fail_on:
        sev_order  = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'MED':2,'LOW':3}
        threshold  = sev_order.get(args.fail_on, 99)
        violations = [f for f in all_findings
                      if sev_order.get(f.get('severity','INFO'), 99) <= threshold]
        if violations:
            print(f"\n\033[31m✗ {len(violations)} finding(s) at {args.fail_on}+ level\033[0m")
            sys.exit(1)

    print("\n\033[32m✓ Scan complete\033[0m\n")
    sys.exit(0)


def _print_text(findings, summary, quiet):
    """Print text output."""
    if not quiet:
        sev_colors = {
            'CRITICAL': '\033[31m',
            'HIGH':     '\033[33m',
            'MED':      '\033[33m',
            'MEDIUM':   '\033[33m',
            'LOW':      '\033[32m',
        }
        reset = '\033[0m'

        for f in findings[:50]:
            sev   = f.get('severity', 'INFO')
            color = sev_colors.get(sev, '')
            ftype = f.get('type', '?')
            ffile = Path(f.get('file', '?')).name
            fline = f.get('line', '?')
            print(f" {color}[{sev}]{reset} {ftype} — {ffile}:{fline}")

        if len(findings) > 50:
            print(f" ... and {len(findings)-50} more findings")

    print(f"\n Total: {summary.get('total_findings',0)} | "
          f"Critical: {summary.get('critical',0)} | "
          f"High: {summary.get('high',0)}")


def _json_output(findings, summary, args):
    """Write JSON output."""
    data = {
        'findings': findings[:200],
        'summary':  summary,
        'target':   args.target,
    }

    if args.output:
        out_path = Path(args.output)
        if out_path.is_dir() or str(args.output).endswith('/'):
            out_path.mkdir(parents=True, exist_ok=True)
            out_file = out_path / 'r3con_results.json'
        else:
            out_file = out_path
        out_file.write_text(json.dumps(data, indent=2))
        return str(out_file)
    else:
        print(json.dumps(data, indent=2))
        return None


if __name__ == '__main__':
    main()

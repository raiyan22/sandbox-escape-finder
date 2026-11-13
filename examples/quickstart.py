"""Quickstart: run both halves of SandboxEscapeFinder end-to-end.

This is the exact snippet shape from the task description, fleshed out into a
runnable script. It:

  1. runs the StaticAnalyzer on one suspicious snippet and prints the findings;
  2. runs the DynamicProber over the full seeded corpus against real
     RestrictedPython, prints a results table, and prints the
     false-positive / false-negative summary.

Run it with::

    python examples/quickstart.py
"""

from sandbox_escape_finder import DynamicProber, StaticAnalyzer


def demo_static() -> None:
    print("=" * 70)
    print("STATIC ANALYSIS")
    print("=" * 70)

    source_code = "().__class__.__bases__[0].__subclasses__()"
    config = {"min_confidence": 0.0}

    analyzer = StaticAnalyzer(config)
    findings = analyzer.scan(source_code)

    print(f"source: {source_code}\n")
    for f in findings:
        print(f"  [{f['confidence']:.2f}] {f['technique']:24} "
              f"line {f['lineno']} col {f['col_offset']}: {f['snippet']}")


def demo_dynamic() -> None:
    print("\n" + "=" * 70)
    print("DYNAMIC PROBING vs. real RestrictedPython")
    print("=" * 70)

    config = {"seed": 1}
    # In production the prober builds a real RestrictedPython sandbox and a
    # CanaryOracle inside an isolated subprocess, so we do not pass our own
    # sandbox_exec / oracle here.
    prober = DynamicProber(config=config)
    report = prober.run()  # defaults to the built-in attributed corpus

    header = f"{'payload':30}{'technique':24}{'flag':5}{'ran':5}{'ESCAPED':8}"
    print(header)
    print("-" * len(header))
    for row in sorted(report, key=lambda r: r["id"]):
        print(f"{row['id']:30}{row['technique']:24}"
              f"{'Y' if row['static_flagged'] else '-':5}"
              f"{'Y' if row['executed'] else '-':5}"
              f"{'YES' if row['escaped'] else 'no':8}")

    summary = prober.analyze(report)
    print("\nSummary:")
    print(f"  total payloads          : {summary['total']}")
    print(f"  statically flagged      : {summary['statically_flagged']}")
    print(f"  executed in sandbox     : {summary['executed']}")
    print(f"  actually escaped        : {summary['escaped']}")
    print(f"  flagged but no escape   : {len(summary['flagged_but_no_escape'])}")
    print(f"  escaped but not flagged : {len(summary['escaped_but_not_flagged'])}")


if __name__ == "__main__":
    demo_static()
    demo_dynamic()

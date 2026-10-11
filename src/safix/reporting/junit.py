"""JUnit XML report of a scan result (for CI dashboards).

Each finding becomes a <testcase>; active findings carry a <failure>, suppressed findings are
<skipped>. Findings are grouped into one <testsuite> per category.
"""

from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from ..engine.runner import ScanResult
from ..model.finding import Finding


def _attr(v) -> str:
    return quoteattr("" if v is None else str(v))


def _testcase(f: Finding) -> str:
    name = f"{f.rule_id}: {f.title}"
    if f.msg_seq is not None:
        name += f" (seq {f.msg_seq})"
    detail = escape(f"{f.message}\nvectors: {', '.join(f.vector_ids)}\n"
                    f"session: {f.session}\nremediation: {f.remediation or ''}")
    body = (f"<skipped message={_attr(f.suppressed_by or 'suppressed')}/>" if f.suppressed
            else f"<failure message={_attr(f.title)} type={_attr(f.severity.value)}>{detail}</failure>")
    return (f'<testcase classname={_attr(f.category)} name={_attr(name)} '
            f'time="0">{body}</testcase>')


def render(result: ScanResult) -> str:
    by_cat: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category or "UNKNOWN", []).append(f)

    suites = []
    total_tests = total_fail = total_skip = 0
    for cat, findings in sorted(by_cat.items()):
        fails = sum(1 for f in findings if not f.suppressed)
        skips = sum(1 for f in findings if f.suppressed)
        total_tests += len(findings)
        total_fail += fails
        total_skip += skips
        cases = "".join(_testcase(f) for f in findings)
        suites.append(
            f'<testsuite name={_attr("SAFIX." + cat)} tests="{len(findings)}" '
            f'failures="{fails}" skipped="{skips}">{cases}</testsuite>')

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites name="SAFIX" tests="{total_tests}" failures="{total_fail}" '
        f'skipped="{total_skip}">\n' + "\n".join(suites) + "\n</testsuites>\n"
    )

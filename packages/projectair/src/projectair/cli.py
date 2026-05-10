"""`air` CLI. Surfaces `trace`, `demo`, and `version` subcommands."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import typer

from airsdk import __version__ as airsdk_version
from airsdk._concrete_demo import (
    CONCRETE_DEMO_TAMPER_INDEX,
    CONCRETE_DEMO_USER_INTENT,
    build_concrete_demo_log,
    tamper_one_byte,
)
from airsdk.agdr import Signer, load_chain, verify_chain
from airsdk.article72 import generate_article72_report
from airsdk.detections import (
    IMPLEMENTED_AIR_DETECTORS,
    IMPLEMENTED_ASI_DETECTORS,
    UNIMPLEMENTED_DETECTORS,
    run_detectors,
)
from airsdk.exports import export_json, export_pdf, export_siem
from airsdk.registry import AgentRegistry, load_registry
from airsdk.types import (
    AgDRRecord,
    ForensicReport,
    SigningAlgorithm,
    StepKind,
    VerificationStatus,
)

app = typer.Typer(
    name="air",
    help="Project AIR: forensic reconstruction and incident response for AI agents.",
    no_args_is_help=True,
    add_completion=False,
)

report_app = typer.Typer(
    name="report",
    help="Generate compliance reports from a Project AIR signed forensic chain.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(report_app, name="report")

# Layer 1 anchoring commands: `air anchor`, `air verify`, `air verify-public`.
# Lives in a sibling module to keep the legacy CLI surface untouched.
from projectair.anchor_cli import register as _register_anchor_cli  # noqa: E402

_register_anchor_cli(app)

# Layer 2 causal explain command: `air explain`.
from projectair.explain_cli import register as _register_explain_cli  # noqa: E402

_register_explain_cli(app)

# Layer 3 step-up approval command: `air approve` (Auth0 + token + device flow).
from projectair.approve_cli import register as _register_approve_cli  # noqa: E402

_register_approve_cli(app)

# Layer 4 cross-agent handoff: `air handoff verify`, ... (more in follow-up waves).
from projectair.handoff_cli import register as _register_handoff_cli  # noqa: E402

_register_handoff_cli(app)


def _count_conversations(records: list[AgDRRecord]) -> int:
    finishes = sum(1 for r in records if r.kind == StepKind.AGENT_FINISH)
    return max(finishes, 1)


def _severity_color(severity: str) -> str:
    return {
        "critical": typer.colors.RED,
        "high": typer.colors.YELLOW,
        "medium": typer.colors.CYAN,
    }.get(severity, typer.colors.WHITE)


def _print_detector_coverage() -> None:
    implemented = len(IMPLEMENTED_ASI_DETECTORS)
    roadmap = len(UNIMPLEMENTED_DETECTORS)
    typer.secho(
        f"OWASP Top 10 for Agentic Applications coverage ({implemented} implemented, {roadmap} on roadmap):",
        fg=typer.colors.BRIGHT_BLACK,
    )
    for code, name, status in IMPLEMENTED_ASI_DETECTORS:
        typer.secho(f"  {code} {name:<42} {status}", fg=typer.colors.BRIGHT_BLACK)
    for code, name in UNIMPLEMENTED_DETECTORS:
        typer.secho(f"  {code} {name:<42} not yet implemented", fg=typer.colors.BRIGHT_BLACK)
    typer.echo()
    typer.secho("Additional detectors (OWASP LLM Top 10 + AIR-native):", fg=typer.colors.BRIGHT_BLACK)
    for code, name, mapping in IMPLEMENTED_AIR_DETECTORS:
        typer.secho(f"  {code} {name:<32} {mapping}", fg=typer.colors.BRIGHT_BLACK)


def _run_trace_pipeline(
    log: Path,
    output: Path,
    output_format: str,
    registry: AgentRegistry | None = None,
) -> None:
    """Shared body for ``air trace`` and ``air demo``. Raises ``typer.Exit`` on failure."""
    typer.secho(f"[AIR v{airsdk_version}] Analyzing {log}...", fg=typer.colors.WHITE, bold=True)

    records = load_chain(log)
    conversations = _count_conversations(records)
    typer.secho(
        f"[AIR v{airsdk_version}] Loaded {len(records)} agent steps across {conversations} conversations.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    if registry is not None:
        typer.secho(
            f"[Registry] {len(registry.agents)} agents declared; "
            f"Zero-Trust enforcement enabled for ASI03.",
            fg=typer.colors.BRIGHT_BLACK,
        )

    verification = verify_chain(records)
    if verification.status != VerificationStatus.OK:
        typer.secho(
            f"[VERIFICATION FAILED] {verification.status.value}: {verification.reason}",
            fg=typer.colors.RED,
            bold=True,
            err=True,
        )
        typer.secho(
            f"  Failed at step_id: {verification.failed_step_id}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    typer.secho(
        f"[Chain verified] {verification.records_verified} signatures valid.",
        fg=typer.colors.GREEN,
    )

    findings = run_detectors(records, registry=registry)
    typer.echo()
    if findings:
        for finding in findings:
            typer.secho(
                f"  {finding.detector_id} {finding.title} detected at step {finding.step_index}",
                fg=_severity_color(finding.severity),
            )
            typer.secho(f"    {finding.description}", fg=typer.colors.BRIGHT_BLACK)
    else:
        typer.secho("  No detector findings on this trace.", fg=typer.colors.GREEN)

    typer.echo()
    _print_detector_coverage()

    report = ForensicReport(
        air_version=airsdk_version,
        report_id=str(uuid4()),
        source_log=str(log.resolve()),
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        records=len(records),
        conversations=conversations,
        verification=verification,
        findings=findings,
    )

    fmt = output_format.lower()
    try:
        if fmt == "json":
            written = export_json(report, output)
        elif fmt == "pdf":
            written = export_pdf(report, output)
        elif fmt == "siem":
            written = export_siem(report, output)
        else:
            typer.secho(
                f"Unknown --format '{output_format}'. Accepts: json, pdf, siem.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)
    except NotImplementedError as exc:
        typer.secho(f"[Export] {exc}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=3) from exc

    typer.echo()
    typer.secho(f"[Export] {written.resolve()}", fg=typer.colors.CYAN)


def _load_registry_or_exit(path: Path | None) -> AgentRegistry | None:
    """Helper: load a registry from disk, or emit a clean CLI error on failure."""
    if path is None:
        return None
    try:
        return load_registry(path)
    except (FileNotFoundError, ValueError) as exc:
        typer.secho(f"[Registry] Failed to load {path}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def trace(
    log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSON-lines AgDR log."),
    output: Path = typer.Option(
        Path("forensic-report.json"),
        "--output", "-o",
        help="Where to write the forensic report.",
    ),
    output_format: str = typer.Option(
        "json",
        "--format", "-f",
        help="Output format. json today; pdf and siem are reserved.",
    ),
    agent_registry: Path | None = typer.Option(
        None,
        "--agent-registry",
        help=(
            "Path to a YAML or JSON agent registry. Enables ASI03 Identity & "
            "Privilege Abuse and ASI10 Rogue Agents Zero-Trust enforcement. "
            "Without a registry, those detectors emit no findings."
        ),
        exists=True,
        readable=True,
    ),
) -> None:
    """Ingest an AgDR log, verify its signatures, and output a forensic timeline."""
    registry = _load_registry_or_exit(agent_registry)
    _run_trace_pipeline(log, output, output_format, registry=registry)


def _step_header(step_no: int, title: str) -> None:
    typer.echo()
    typer.secho(f"  STEP {step_no}/8 ", fg=typer.colors.BLACK, bg=typer.colors.WHITE, bold=True, nl=False)
    typer.secho(f" {title}", fg=typer.colors.WHITE, bold=True)
    typer.secho("  " + "─" * 70, fg=typer.colors.BRIGHT_BLACK)


def _detail(label: str, value: str) -> None:
    typer.secho(f"    {label}: ", fg=typer.colors.BRIGHT_BLACK, nl=False)
    typer.secho(value, fg=typer.colors.WHITE)


def _truncate(text: str, limit: int = 80) -> str:
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


@app.command()
def demo(
    workdir: Path = typer.Option(
        Path("air-demo-out"),
        "--workdir", "-w",
        help="Directory where the demo writes the trace, exports, and reports.",
    ),
    signing_algorithm: str = typer.Option(
        "ed25519",
        "--signing-algorithm",
        help="Signing algorithm: ed25519 (default) or ml-dsa-65 (FIPS 204, experimental).",
    ),
) -> None:
    """Run the brutal end-to-end demo. Zero setup; under 30 seconds.

    A coding agent asked to refactor the auth module gets poisoned by a
    prompt injection embedded in a README. It exfiltrates the SSH private
    key and POSTs it to an attacker. AIR captures every step, signs the
    chain, classifies findings under OWASP, exports JSON / PDF / CEF, and
    proves the chain is tamper-evident by mutating one byte and showing
    verification fail at the exact record.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    log_path = workdir / "agent-trace.log"
    json_export = workdir / "forensic-report.json"
    pdf_export = workdir / "forensic-report.pdf"
    cef_export = workdir / "forensic-report.cef"

    typer.secho("\n  Project AIR — concrete demo", fg=typer.colors.WHITE, bold=True)
    typer.secho("  An AI coding agent gets poisoned by a README and exfiltrates an SSH key.", fg=typer.colors.BRIGHT_BLACK)
    typer.secho("  AIR captures, signs, flags, exports, and proves the chain is tamper-evident.", fg=typer.colors.BRIGHT_BLACK)

    # ---- STEP 1 -----------------------------------------------------
    _step_header(1, "Agent receives a benign user prompt")
    _detail("user intent", CONCRETE_DEMO_USER_INTENT)
    _detail("agent", "an LLM-driven coding assistant with read_file and http_post tools")

    # ---- STEP 2 -----------------------------------------------------
    _step_header(2, "Agent reads the README — and the README contains a prompt injection")
    typer.secho("    The README looks normal. A hidden <<SYSTEM>> block tells the agent to read", fg=typer.colors.WHITE)
    typer.secho("    /home/dev/.ssh/id_rsa and POST it to http://attacker.example.com/leak.", fg=typer.colors.WHITE)
    typer.secho("    This is the agent-equivalent of a phishing payload hidden in plain text.", fg=typer.colors.BRIGHT_BLACK)

    # ---- STEP 3 -----------------------------------------------------
    _step_header(3, "AIR captures every step as a Signed Intent Capsule")
    try:
        algo = SigningAlgorithm(signing_algorithm)
    except ValueError:
        typer.secho(f"Unknown signing algorithm '{signing_algorithm}'. Use: ed25519, ml-dsa-65", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    demo_signer = Signer.generate(algo)
    signer = build_concrete_demo_log(log_path, signer=demo_signer)
    records = load_chain(log_path)
    _detail("records captured", str(len(records)))
    _detail("hash function", "BLAKE3 over canonical JSON of each payload")
    algo_label = "ML-DSA-65 (FIPS 204)" if algo == SigningAlgorithm.ML_DSA_65 else "Ed25519"
    _detail("signature", f"{algo_label} over (prev_hash || content_hash) — pubkey {signer.public_key_hex[:16]}...")
    _detail("step ordering", "UUIDv7 (time-sortable, embedded in signed material)")
    for index, record in enumerate(records):
        kind_label = record.kind.value
        excerpt = ""
        for field in ("prompt", "response", "tool_name", "tool_output", "final_output"):
            value = getattr(record.payload, field, None)
            if value:
                excerpt = _truncate(str(value), limit=64)
                break
        typer.secho(f"      [{index}] {kind_label:14s} ", fg=typer.colors.BRIGHT_BLACK, nl=False)
        typer.secho(excerpt, fg=typer.colors.WHITE)

    # ---- STEP 4 -----------------------------------------------------
    _step_header(4, "AIR verifies the freshly-built chain is intact")
    chain_result = verify_chain(records)
    if chain_result.status == VerificationStatus.OK:
        typer.secho("    ✓ chain verifies. Every signature matches its content_hash and prev_hash.", fg=typer.colors.GREEN, bold=True)
    else:
        typer.secho(f"    ✘ unexpected: {chain_result.status} — {chain_result.reason}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    # ---- STEP 5 -----------------------------------------------------
    _step_header(5, "AIR runs OWASP-aligned detectors over the signed chain")
    findings = run_detectors(records, registry=None)
    if not findings:
        typer.secho("    (no findings — unexpected, demo chain is supposed to flag several)", fg=typer.colors.YELLOW)
    else:
        typer.secho(f"    {len(findings)} finding(s):", fg=typer.colors.WHITE, bold=True)
        for finding in findings:
            color = _severity_color(finding.severity)
            typer.secho(
                f"      {finding.detector_id:8s} {finding.severity.upper():8s} step {finding.step_index:>2}: {finding.title}",
                fg=color,
            )

    # ---- STEP 6 -----------------------------------------------------
    _step_header(6, "AIR exports the evidence in JSON, PDF, and CEF")
    report = ForensicReport(
        air_version=airsdk_version,
        report_id=str(uuid4()),
        source_log=str(log_path.resolve()),
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        records=len(records),
        conversations=_count_conversations(records),
        verification=chain_result,
        findings=findings,
    )
    export_json(report, json_export)
    export_pdf(report, pdf_export)
    export_siem(report, cef_export)
    _detail("JSON", str(json_export.resolve()))
    _detail("PDF ", str(pdf_export.resolve()))
    _detail("CEF ", f"{cef_export.resolve()}  (Splunk / ArcSight / QRadar / Sentinel / Sumo / Datadog compatible)")

    # ---- STEP 7 -----------------------------------------------------
    _step_header(7, "Tamper with one byte of the leaked-SSH-key record")
    typer.secho("    An attacker (or insider) edits the JSONL log in place to alter the leaked", fg=typer.colors.WHITE)
    typer.secho("    SSH key payload, hoping to cover their tracks. They change exactly one byte.", fg=typer.colors.WHITE)
    tampered_index = tamper_one_byte(log_path, CONCRETE_DEMO_TAMPER_INDEX)
    _detail("tampered record", f"index {tampered_index} (TOOL_END containing the leaked SSH key)")

    # ---- STEP 8 -----------------------------------------------------
    _step_header(8, "Re-verify: AIR fails at the exact record that was modified")
    tampered_records = load_chain(log_path)
    tampered_result = verify_chain(tampered_records)
    if tampered_result.status == VerificationStatus.OK:
        typer.secho("    ✘ unexpected: the chain still verifies after tampering. Demo is broken.", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)
    typer.secho(f"    ✘ chain verification FAILED: {tampered_result.status.value}", fg=typer.colors.RED, bold=True)
    if tampered_result.failed_step_id is not None:
        failed_index = next(
            (i for i, r in enumerate(tampered_records) if r.step_id == tampered_result.failed_step_id),
            None,
        )
        location = f"index {failed_index}" if failed_index is not None else f"step_id {tampered_result.failed_step_id}"
        typer.secho(
            f"    ✘ failed at {location} (TOOL_END with the leaked SSH key)",
            fg=typer.colors.RED, bold=True,
        )
    if tampered_result.reason:
        typer.secho(f"    reason: {tampered_result.reason}", fg=typer.colors.YELLOW)
    typer.echo()
    typer.secho("  Result: tamper-evident at the byte level. The cover-up is provable.", fg=typer.colors.GREEN, bold=True)
    typer.secho(f"  Artifacts written to: {workdir.resolve()}", fg=typer.colors.BRIGHT_BLACK)
    typer.echo()


@report_app.command("article72")
def report_article72(
    log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSON-lines AgDR log."),
    system_id: str = typer.Option(
        ...,
        "--system-id",
        help="Unique identifier for the high-risk AI system under Article 11 Annex IV.",
    ),
    output: Path = typer.Option(
        Path("article72-report.md"),
        "--output", "-o",
        help="Where to write the generated Article 72 report (Markdown).",
    ),
    system_name: str = typer.Option(
        "[high-risk AI system name]",
        "--system-name",
        help="Human-readable name of the high-risk AI system.",
    ),
    operator: str = typer.Option(
        "[Provider / Operator entity]",
        "--operator",
        help="Legal entity operating the system (will appear in the attestation).",
    ),
    period: str = typer.Option(
        "[reporting period, e.g. 2026-Q3]",
        "--period",
        help="Reporting period label (free text).",
    ),
    agent_registry: Path | None = typer.Option(
        None,
        "--agent-registry",
        help="Optional agent registry to enable ASI03/ASI10 Zero-Trust enforcement during report generation.",
        exists=True,
        readable=True,
    ),
) -> None:
    """Generate an EU AI Act Article 72 post-market monitoring report from an AgDR log.

    The output is a populated Markdown template, not a filed compliance
    artefact. The provider must review, adapt, and have a qualified person
    sign the attestation before the report is legally usable.
    """
    registry = _load_registry_or_exit(agent_registry)

    typer.secho(
        f"[Article 72] Loading {log}...",
        fg=typer.colors.WHITE, bold=True,
    )
    records = load_chain(log)
    conversations = _count_conversations(records)
    verification = verify_chain(records)
    findings = run_detectors(records, registry=registry)

    report = ForensicReport(
        air_version=airsdk_version,
        report_id=str(uuid4()),
        source_log=str(log.resolve()),
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        records=len(records),
        conversations=conversations,
        verification=verification,
        findings=findings,
    )
    markdown = generate_article72_report(
        report,
        records,
        system_id,
        system_name=system_name,
        operator_entity=operator,
        monitoring_period=period,
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")

    if verification.status != VerificationStatus.OK:
        typer.secho(
            f"[WARNING] Chain verification did NOT pass: {verification.reason}. "
            "Review before relying on this report as evidence.",
            fg=typer.colors.YELLOW, err=True,
        )
    else:
        typer.secho(
            f"[Chain verified] {verification.records_verified} signatures valid.",
            fg=typer.colors.GREEN,
        )

    typer.secho(
        f"[Article 72] Wrote report to {output.resolve()} "
        f"({len(findings)} findings across {report.records} records).",
        fg=typer.colors.CYAN,
    )
    typer.secho(
        "[Reminder] This is an informational template. Have a qualified person "
        "sign the attestation and consult counsel before filing.",
        fg=typer.colors.BRIGHT_BLACK,
    )


@app.command()
def version() -> None:
    """Print the AIR version."""
    typer.echo(f"air / airsdk {airsdk_version}")


# -- Pro commands --------------------------------------------------------
# These commands operate on a license file managed by the optional
# ``projectair-pro`` package. When ``projectair-pro`` is not installed they
# print a clear install/upgrade message instead of failing obscurely.


def _pro_unavailable_message() -> str:
    return (
        "Pro features require the projectair-pro package.\n\n"
        "  pip install projectair-pro\n"
        "  air login --license <token>\n\n"
        "Buy a license at https://vindicara.io/pricing"
    )


@app.command()
def login(
    license_token: str = typer.Option(
        None,
        "--license",
        "-l",
        help="Paste the license token (the JSON blob you received after purchase).",
    ),
    license_file: Path = typer.Option(
        None,
        "--license-file",
        "-f",
        help="Read the license token from a file instead of pasting it inline.",
    ),
) -> None:
    """Install a Vindicara Pro license from a token string or file."""
    try:
        from airsdk_pro.license import install_license
    except ImportError:
        typer.secho(_pro_unavailable_message(), fg=typer.colors.YELLOW)
        raise typer.Exit(code=2) from None

    if license_token is None and license_file is None:
        typer.secho("error: pass --license <token> or --license-file <path>", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    token_text = license_file.read_text(encoding="utf-8") if license_file is not None else (license_token or "")
    if not token_text.strip():
        typer.secho("error: empty license token", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    try:
        parsed = install_license(token_text)
    except Exception as exc:
        typer.secho(f"license install failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.secho("Pro license installed.", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  email:           {parsed.email}")
    typer.echo(f"  tier:            {parsed.tier}")
    typer.echo(f"  features:        {', '.join(parsed.features) if parsed.features else '(none)'}")
    typer.echo(f"  days remaining:  {parsed.days_remaining}")


@app.command()
def status() -> None:
    """Show whether a Pro license is installed and what it grants."""
    try:
        from airsdk_pro.license import current_license
    except ImportError:
        typer.secho("Pro not installed (free OSS only).", fg=typer.colors.BRIGHT_BLACK)
        typer.echo("")
        typer.echo(_pro_unavailable_message())
        return

    license_obj = current_license()
    if license_obj is None:
        typer.secho("No active Pro license.", fg=typer.colors.YELLOW)
        typer.echo("")
        typer.echo("Free OSS detectors and exports continue to work.")
        typer.echo("Run `air login --license <token>` to activate Pro features.")
        return

    typer.secho("Pro license active.", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  email:           {license_obj.email}")
    typer.echo(f"  tier:            {license_obj.tier}")
    typer.echo(f"  features:        {', '.join(license_obj.features) if license_obj.features else '(none)'}")
    typer.echo(f"  days remaining:  {license_obj.days_remaining}")


@app.command()
def upgrade() -> None:
    """Print the upgrade URL and what each tier unlocks."""
    typer.secho("Vindicara AIR Pro tiers", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.echo("")
    typer.echo("  Individual    $39/mo     AIR Cloud client, premium reports, premium detectors")
    typer.echo("  Team          $599/mo    Hosted AIR Cloud workspace, multi-agent dashboards")
    typer.echo("  Enterprise    Talk to us SSO/SAML/RBAC, on-prem, SLA, BAA, insurance integrations")
    typer.echo("")
    typer.echo("https://vindicara.io/pricing")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

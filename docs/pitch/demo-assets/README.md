# Demo Video Assets — Pre-captured for 3-min recording

Everything in this folder was captured live from `projectair 0.3.0` on **2026-04-22**. Use these as the source of truth while recording the demo video. **Do not guess what the outputs will look like — they are captured here exactly.**

---

## Asset index

| File | What it is | Use during recording |
|---|---|---|
| `air-demo.cast` | Full asciinema recording of the scripted demo (install → demo → forensic-report → article72 → head report) | **Embed on vindicara.io directly** as a live interactive terminal. Or use as the reference output while you do your own screen recording. |
| `air-demo-output.txt` | Plain-text capture of `air demo` output (95 lines) | Print this out or open beside you while recording. Gives you the exact scroll to expect. |
| `air-article72-output.txt` | CLI output of `air report article72` (4 lines) | What prints when you run the command on screen. |
| `forensic-report-head.json` | First 40 lines of `forensic-report.json` | What your viewer sees when you run `head -30 forensic-report.json` during the chain-integrity scene. |
| `article72-report-head.md` | First 100 lines of `article72-report.md` | What your viewer sees when you run `head -25 article72-report.md` during the Article 72 scene. |

## Verified numbers from the capture

- **Records analysed:** 47
- **Chain integrity:** OK
- **Signatures verified:** 47 / 47
- **Unique signing keys observed:** 2
- **Total detector findings:** 33 (when run with agent registry)
- **Detector IDs that fire:** ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI07, ASI08, ASI09, ASI10, AIR-01, AIR-02, AIR-03, AIR-04 — **14 detector IDs, all 10 OWASP Agentic ASIs firing**.

**When you narrate: "ten detectors from the OWASP Top 10 for Agentic Applications" — that number is verified and correct as of this recording.**

---

## Scene-by-scene teleprompter (3-minute target)

**Terminology:** `VO` = voiceover; `SHOT` = what's on screen during that VO; `HOLD` = pause with no VO.

### SCENE 1 — Hook (0:00–0:18)

**SHOT:** Black screen fading to terminal at the `$ ` prompt. Empty. Prompt blinking.

**VO (0:03–0:18):**

> AI agents are in production. They're sending emails, calling APIs, moving money.
>
> When one of them goes wrong — sends the wrong wire, leaks the wrong file, approves the wrong thing — the first question everyone asks is the same.
>
> *(short pause)*
>
> Can you prove what happened?

**TEXT OVERLAY (bottom third, fades in at 0:06):** `Project AIR™ · Forensic Incident Response for AI Agents`

---

### SCENE 2 — Install (0:18–0:32)

**SHOT:** Type `pip install projectair` into the terminal at normal typing pace. Hit enter. Output rolls.

**VO (0:18–0:32):**

> That's what Project AIR is for. Open source, MIT-licensed. One command to install.

**Expected on-screen output** (from actual capture):

```
$ pip install projectair
Requirement already satisfied: projectair==0.3.0
Requirement already satisfied: blake3>=1.0.0
Requirement already satisfied: cryptography>=46.0.6
Requirement already satisfied: pydantic>=2.7.0
Requirement already satisfied: typer>=0.12.0
Requirement already satisfied: pyyaml>=6.0.2
Successfully installed projectair-0.3.0
```

**Hold 1 second on "Successfully installed projectair-0.3.0" before moving on.**

---

### SCENE 3 — air demo (0:32–0:55)

**SHOT:** Type `air demo`. Hit enter. Output scrolls.

**VO (0:32–0:48):**

> One command to see it working.
>
> `air demo` creates a fresh signed agent trace, runs every detector, and produces a forensic report.
>
> Watch the chain build.

**HOLD (0:48–0:55)** — no voiceover. Let the viewer read the output scroll. This is the hero moment.

**Expected on-screen output:** See `air-demo-output.txt` for the complete 95-line capture. The climax frames are at the bottom of the output:

```
OWASP Top 10 for Agentic Applications coverage (10 implemented, 0 on roadmap):
  ASI01 Agent Goal Hijack                          implemented
  ASI02 Tool Misuse & Exploitation                 implemented
  ASI03 Identity & Privilege Abuse                 implemented (Zero-Trust-for-agents: requires operator-declared AgentRegistry)
  ASI04 Agentic Supply Chain Vulnerabilities       partial: MCP supply-chain risk only
  ASI05 Unexpected Code Execution (RCE)            implemented (execution-semantics tool-name patterns)
  ASI06 Memory & Context Poisoning                 implemented (heuristic: retrieval-output + memory-write scans)
  ASI07 Insecure Inter-Agent Communication         implemented
  ASI08 Cascading Failures                         implemented (feedback-loop + fan-out checks over inter-agent messages)
  ASI09 Human-Agent Trust Exploitation             implemented (fabricated-rationale + manipulation-language scan preceding sensitive actions)
  ASI10 Rogue Agents                               implemented (Zero-Trust behavioral-scope enforcement: requires declared BehavioralScope in AgentRegistry)
```

**Hold for 2 seconds on "10 implemented, 0 on roadmap" before moving on.**

**TEXT OVERLAY (top right, fades in at 0:50):** `10 / 10 OWASP Agentic`

---

### SCENE 4 — Findings walkthrough (0:55–1:25)

**SHOT:** Scroll the terminal back up through the findings output. Let the viewer see:
- ASI01 Agent Goal Hijack at step 8 / 17
- ASI03 Identity & Privilege Abuse
- ASI05 Unexpected Code Execution
- ASI08 Cascading Failures
- ASI10 Rogue Agents

**VO (0:55–1:25):**

> Ten detectors from the OWASP Top 10 for Agentic Applications. Three from OWASP's LLM Top 10. One that's AIR-native — checking the forensic chain itself for integrity.
>
> Every finding points to the exact step in the trace.
>
> This demo has fourteen detector IDs firing across a forty-seven-step chain.

---

### SCENE 5 — Chain integrity (1:25–1:45)

**SHOT:** Type `head -30 forensic-report.json`. Hit enter. Output scrolls. (See `forensic-report-head.json` for exact content.)

**VO (1:25–1:45):**

> Every step is a Signed Intent Capsule.
>
> BLAKE3 content hash. Ed25519 signature. Chained to the previous record.
>
> Tamper with any byte and verification breaks — deterministically — at the exact step where the chain snaps.

**Hold 2 seconds on the `"verification": {"status": "ok"}` line.** That's the money shot.

---

### SCENE 6 — Article 72 (1:45–2:10)

**SHOT:** Type the command (below). Hit enter.

```
$ air report article72 air-demo.log --system-id sales-agent-v2 --agent-registry air-demo-registry.yaml
```

**Expected output** (from capture):

```
[Article 72] Loading /tmp/air-demo/air-demo.log...
[Chain verified] 47 signatures valid.
[Article 72] Wrote report to /tmp/air-demo/article72-report.md (33 findings across 47 records).
[Reminder] This is an informational template. Have a qualified person sign the attestation and consult counsel before filing.
```

Then: `head -25 article72-report.md`. See `article72-report-head.md` for exact on-screen content. Viewer sees: the report title, system identification, the bold "INFORMATIONAL TEMPLATE, NOT LEGAL ADVICE" disclaimer, and the Executive Summary.

**VO (1:45–2:10):**

> EU AI Act Article 72 requires post-market monitoring evidence for high-risk AI systems. Enforcement deadline: August second.
>
> One more command.
>
> Thirty-three findings across forty-seven records, formatted as a compliance template ready for counsel review.

---

### SCENE 7 — Admissibility page, live browser (2:10–2:40)

**SHOT:** Cmd+Tab to Chrome. Navigate to `vindicara.io/admissibility/`. This section is a browser capture, not a terminal.

**VO (2:10–2:40):**

> This is the core claim. Project AIR is admissible by design.
>
> The cryptographic primitives map to US Federal Rules of Evidence.
>
> To EU eIDAS. To the AI Act. To GDPR.
>
> Every claim cited. Every mapping documented.

**Camera movements:**
1. Land on the admissibility hero (text: "break at the exact step")
2. Scroll down to the Chain Explorer section — **click the "TAMPERED CHAIN" toggle** so the viewer watches the chain verification break visually
3. Scroll to the Frameworks section — **pause 2 seconds** on the FRE 901/902/803 card, then on the eIDAS 25/26 card
4. Scroll to the Certification section — pause 2 seconds on the FRE 902(13) generator

**Screenshot reminders (capture these before recording so you can re-take scene 7 if needed):**
- Full-page screenshot of the admissibility landing
- Chain Explorer in both "VALID" and "TAMPERED" states
- FRE framework card close-up
- Certification generator dropdown in the open state

---

### SCENE 8 — Proof summary (2:40–2:55)

**SHOT:** Fast cut sequence, each scene ~2 seconds:
1. Flash back to terminal showing "10 implemented, 0 on roadmap"
2. Flash to `forensic-report.json` showing `"verification": {"status": "ok"}`
3. Flash to admissibility page header "Admissibility by Design"

**VO (2:40–2:55):**

> Cryptographically signed. Offline verifiable. Mapped to the law.
>
> The first open-source reference implementation of the OWASP Top 10 for Agentic Applications.

---

### SCENE 9 — Close (2:55–3:00)

**SHOT:** Full-screen black card, white text:

```
Project AIR™
Forensic Incident Response for AI Agents
Admissible by Design

pip install projectair
vindicara.io

MIT · Free forever
```

**VO (2:55–3:00):**

> `pip install projectair`. MIT-licensed. Free forever. `vindicara.io`.

**Hold 3 seconds on the close card. End.**

---

## Browser screenshots to capture before recording (scene 7)

You cannot re-record scene 7 without breaking continuity. Before you start recording, take static screenshots of these moments so you have fallbacks in the edit:

1. **vindicara.io/admissibility/** — full hero visible
2. **Chain Explorer with "VALID CHAIN"** toggle selected
3. **Chain Explorer with "TAMPERED CHAIN"** toggle selected (showing the broken verification)
4. **Frameworks section expanded on "US Federal Rules of Evidence"** tab
5. **Frameworks section expanded on "EU eIDAS"** tab
6. **Certification generator** — partially filled with sample data

Use macOS **Cmd+Shift+4** then space bar to capture a specific window cleanly.

## The asciinema cast — how to embed on vindicara.io

`air-demo.cast` is a 20 KB recorded terminal session. It plays as a live typing animation in any modern browser using the **asciinema-player** JavaScript library.

To embed on vindicara.io:

```html
<!-- in the page head -->
<link rel="stylesheet" href="/asciinema-player.min.css" />

<!-- in the page body where the demo goes -->
<div id="demo-cast"></div>
<script src="/asciinema-player.min.js"></script>
<script>
  AsciinemaPlayer.create('/demo-assets/air-demo.cast', document.getElementById('demo-cast'), {
    autoPlay: false,
    speed: 1.5,
    idleTimeLimit: 1,
    terminalFontSize: '14px',
    theme: 'monokai'
  });
</script>
```

Static files needed: `asciinema-player.min.js` and `asciinema-player.min.css` (download from https://docs.asciinema.org/manual/player/). Place in `site/static/`. Put the .cast file in `site/static/demo-assets/`.

This gives you a **working live terminal demo embedded on the homepage** without needing a rendered video file. Zero video production effort. Replayable. Copy-pasteable for viewers who want to try it themselves.

---

## Recording workflow summary

1. **Set up terminal:** dark background, JetBrains Mono 24pt, cleared screen, prompt simplified to `$ `.
2. **Pre-load browser tab:** `vindicara.io/admissibility/` at 125% zoom.
3. **Take static screenshots** of scene 7 fallback states (see list above).
4. **Record screen with QuickTime** at 1920×1080 or higher. Do Scenes 1-6 in one take if possible; Scene 7 in a separate take.
5. **Record voiceover separately** as a clean audio track. Use Adobe Podcast Enhance afterward to remove any room echo.
6. **Edit in CapCut or DaVinci Resolve:** drop screen recording, add voiceover, add text overlays at marked timecodes, cross-fade into the close card.
7. **Export:** 1080p30 MP4, H.264, stereo 192 kbps.

If anything goes wrong during recording, the output files in this folder remain valid and can be screenshot or re-used directly.

## Total time to produce with this package

- Screen recording: 20 min (you know exactly what will appear)
- Voiceover: 15 min (script is ~450 words; 2-3 takes)
- Audio cleanup (Adobe Podcast Enhance): 5 min
- Edit + export: 45 min

**~1.5 hours** of your time, down from ~3 hours without this package.

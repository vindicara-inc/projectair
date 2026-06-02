# 3-Minute Product Demo Video — Project AIR™

**Use cases:** vindicara.io homepage embed, Hacker News launch post, YouTube, demo for investors, Techstars/HF0/LAUNCH supplementary asset. Cuts down to 60s, 30s, and 15s versions for social.

**Target run time:** 2:55–3:05 (aim for 3:00 flat).

**Format:** screen recording (terminal + browser + optional code editor) with founder voiceover. No face-on-camera required — this is a product demo, not a pitch.

---

## Pre-production setup (do this once before recording)

### Terminal
- **App:** iTerm2 or Terminal.app
- **Theme:** dark background, bright white text
- **Font:** **JetBrains Mono 20pt minimum** (24pt preferred for YouTube clarity)
- **Window size:** 1280×720 (matches 720p output)
- **Prompt:** simplify to `$ ` (`export PS1='$ '`)
- **Clear before each scene:** `clear` between takes

### Working directory
```
mkdir -p /tmp/air-demo && cd /tmp/air-demo
rm -f air-demo.log air-demo-registry.yaml forensic-report.json article72-report.md
```

### Browser
- **App:** Chrome or Arc, full-screen
- **Tabs (pre-loaded, in order):**
  1. `https://vindicara.io/admissibility/`
  2. `https://pypi.org/project/projectair/`
- **Zoom:** 125% for readability at 720p
- **Disable browser chrome:** use fullscreen, cmd+shift+F

### Recording app
- **Option A:** **QuickTime** → File → New Screen Recording. Record entire screen at native resolution. Simple.
- **Option B:** **OBS Studio** (free). More control — record separate audio + video tracks, multi-source, cleaner output.
- **Resolution:** 1920×1080 minimum (2560×1440 preferred for cropping flexibility).
- **Framerate:** 30 fps (smooth text scrolling; 60 fps is overkill).

### Voiceover
- **Record separately** from screen. Screen recording = silent. Voice = separate `.wav` file.
- **Reason:** if you flub a word, re-record just that line, not the whole screen scene.
- Recording tools: QuickTime (audio-only recording), Voice Memos (Mac/iPhone), or Audacity.
- **Mic:** laptop mic is fine if close (6-12 inches from mouth). External USB mic if available.
- **Environment:** small room with soft surfaces (bedroom beats kitchen). If echo, run the audio through Adobe Podcast Enhance after (podcast.adobe.com/enhance — free).

---

## Voiceover script (~450 words, paces to 3:00 at 150 wpm)

### [0:00–0:18] Hook + problem

> [Pause. Black screen, then first command enters.]
>
> AI agents are in production. They're sending emails. They're calling APIs. They're moving money. And when one of them goes wrong — sends the wrong wire, leaks the wrong file, approves the wrong thing — the first question everyone asks is the same.
>
> *[beat]*
>
> Can you prove what happened?

**Visual:** Black screen fading into a terminal. First 3 seconds is just prompt blinking. Text overlay (bottom third): **"Project AIR™ · Forensic Incident Response for AI Agents"**

### [0:18–0:32] Install

> That's what Project AIR is for. It's open source, MIT-licensed. One command to install.

**Visual:** Type and run:
```
$ pip install projectair
```
Let the install output flow. End on: `Successfully installed projectair-0.3.0` — hold for 1 second.

### [0:32–0:55] The demo command

> One command to see it working. `air demo` creates a fresh signed agent trace, runs every detector, and produces a forensic report. Watch the chain build.

**Visual:** Type and run:
```
$ air demo
```

Let the output scroll. The key frame is around the **"OWASP Top 10 for Agentic Applications coverage (10 implemented, 0 on roadmap)"** banner. Pause the voiceover at 0:48 and let the viewer read the findings scroll. Resume voiceover at 0:55.

### [0:55–1:25] Findings walkthrough

> Ten detectors from the OWASP Top 10 for Agentic Applications. Three from OWASP's LLM Top 10. One that's AIR-native — checking the forensic chain itself for integrity. Every finding points to the exact step in the trace. This demo has fourteen detectors firing across a forty-seven-step chain.

**Visual:** Scroll back up through the findings output. Let the viewer see ASI01, ASI03, ASI05, ASI08, ASI10 specifically (the named ones). Text overlay (top right): **"10/10 OWASP Agentic + 3/10 LLM + 1 AIR-native"**

### [1:25–1:45] Chain integrity

> Every step is a Signed Intent Capsule. BLAKE3 content hash, Ed25519 signature, chained to the previous record. Tamper with any byte and verification breaks — deterministically — at the exact step where the chain snaps.

**Visual:** Type and show:
```
$ head -30 forensic-report.json
```
Scroll through. Viewer sees `"content_hash"`, `"signature"`, `"signer_key"`, `"verification": {"status": "ok"}`. This is the **evidence** — hold for 2 seconds on the verification status line.

### [1:45–2:10] Article 72 evidence

> EU AI Act Article 72 requires post-market monitoring evidence for high-risk AI systems. Enforcement deadline: August second. One more command.

**Visual:** Type and run:
```
$ air report article72 air-demo.log --system-id sales-agent-v2
```

Output: `[Article 72] Wrote report to /tmp/air-demo/article72-report.md`

Cut to editor or terminal showing `cat article72-report.md | head -60`. Scroll through. Viewer sees the section headers: **"1. Executive Summary," "2. System Identification (Article 11 Annex IV)," "4. Chain-Integrity Attestation," "9. Attestation."**

### [2:10–2:40] Admissibility architecture (browser)

> This is the core claim: Project AIR is admissible by design. The cryptographic primitives map to US Federal Rules of Evidence, to EU eIDAS, to the AI Act, to GDPR. Every claim cited.

**Visual:** Cmd+Tab to browser. Load `vindicara.io/admissibility/`. Scroll smoothly:
- Hero: "Forensic chain. Break at the exact step."
- Chain explorer section: click "TAMPERED CHAIN" toggle — watch the verification break
- Frameworks section: scroll past US FRE 901/902/803, EU eIDAS 25/26, EU AI Act Article 72, GDPR Article 30

Hold for 2 seconds on the "Sample Certification Template" / FRE 902(13) generator.

### [2:40–2:55] Proof summary

> Cryptographically signed. Offline verifiable. Mapped to the law. First open-source reference implementation of the OWASP Top 10 for Agentic Applications.

**Visual:** Quick cut sequence (each ~2 seconds):
- Terminal coverage banner: "10 implemented, 0 on roadmap"
- Forensic-report.json with verification: ok
- Admissibility page header

### [2:55–3:00] Close

> `pip install projectair`. MIT-licensed. Free forever. `vindicara.io`.

**Visual:** Closing card (black screen, white mono text):

> **Project AIR™**
> *Forensic Incident Response for AI Agents, Admissible by Design*
>
> **pip install projectair**
> **vindicara.io**
>
> MIT · Free forever

Hold 3 seconds. End.

---

## Recording order (do scenes in this sequence)

The demo is easier to record **non-sequentially** because some scenes require pre-loaded state. Record in this order:

1. **Terminal scenes first:** Do scenes 2 (install), 3 (air demo), 5 (head forensic-report), 6 (article72 command). All with clean terminal, no browser switching.
2. **Browser scenes second:** Scene 7 (admissibility page scroll). Keep the browser in one dedicated take.
3. **Voiceover last:** Record the entire 450-word script in one sitting after the screen recording is done, so timing is consistent.
4. **Edit together:** In CapCut or DaVinci Resolve, slot the voiceover on top of the screen recording timeline, adjust where needed.

## Key recording tips

- **Type the commands manually** — do not copy-paste into the terminal on camera. Typing feels authentic. Mistyping once and correcting looks real, not fake.
- **Leave pauses between commands** (2-3 seconds of just the prompt). Makes editing easier — you can trim to the right length later.
- **Record 2-3 takes of each scene.** Keep the best one. First take is usually rough; by take 3 you're comfortable.
- **Watch for notifications.** macOS Do Not Disturb ON. Close Slack, Discord, Messages before recording. Airplane mode optional.
- **Hide the mouse cursor** during terminal scenes if QuickTime lets you. CapCut lets you hide it in post.
- **Use keyboard, not mouse,** in terminal. Makes the demo read as technical.

## Editing checklist

1. Drop screen recording onto timeline (CapCut or DaVinci Resolve)
2. Drop voiceover audio (clean it first through Adobe Podcast Enhance → podcast.adobe.com/enhance)
3. Align voiceover sections to the screen recording scenes (some will need audio/video stretches; sync to the command input, not the output)
4. Add text overlays at the marked moments
5. Add subtle background music, −22 dB (royalty-free, YouTube Audio Library's "Dark Cinematic" tracks work; optional — raw audio is also fine)
6. Add intro card (0.5 sec fade-in, project name) and outro card (hold 3 sec)
7. Trim to exactly 3:00 if possible; 2:55–3:05 is acceptable
8. Export: **1080p30 MP4, H.264, stereo audio at 192 kbps**

## Cut-down versions (use same master recording)

| Length | Cut | Use |
|---|---|---|
| **3:00 master** | Full flow above | vindicara.io homepage, YouTube, investor pitch |
| **60-second social** | Hook (0:00–0:20) + `air demo` coverage table (0:48–0:58) + admissibility-page flash (2:25–2:35) + close (2:55–3:00) | LinkedIn, Twitter, launch post |
| **30-second hook** | Hook (0:00–0:18) + coverage banner flash (0:48–0:55) + close (2:55–3:00) | Pre-roll, paid social |
| **15-second teaser** | Problem question (0:00–0:08) + coverage banner (0:50–0:55) + close card (2:55–3:00) | Shorts, Reels, TikTok |

Record the 3-minute master once. Everything else cuts down from it.

## Post-production

- **Audio cleanup:** Adobe Podcast Enhance (free) for the voiceover track. Denoises + deverbs magically.
- **Video export:** CapCut, DaVinci Resolve, or iMovie all work. Stick with whatever you used for the Techstars/YC videos for consistency.
- **Captions:** YouTube auto-generates. For vindicara.io embed, bake in simple captions (CapCut does this) so viewers scrolling muted still get the story.
- **Thumbnail:** grab a frame of the "10 implemented, 0 on roadmap" coverage banner. High-contrast, on-brand.

## Upload

- **YouTube:** unlisted first for review, then public after you're happy. Title: "Project AIR™ — Forensic Incident Response for AI Agents (3-min demo)"
- **vindicara.io:** embed directly in hero or in a dedicated `/demo` page
- **LinkedIn / Twitter:** use the 60-second cut with captions baked in; raw videos on LinkedIn outperform YouTube embeds

## What to NOT include in this video

- Dollar amounts, pricing, valuation
- Names of competitors
- Customer names or logos (unless you have explicit approval)
- Claims you can't verify in 30 seconds
- Specific OWASP individuals
- "Revolutionary," "10x," "disrupt," "leader"
- Your face — unless you want to; face-on-camera pitch is a separate video category

## Time budget

- Pre-production setup: 15 min
- Screen recording: 45 min (2-3 takes per scene)
- Voiceover recording: 30 min (2-3 takes)
- Audio cleanup: 10 min
- Editing: 90 min
- Export + upload: 15 min

**Total: ~3 hours** for the 3-minute master.

Cut-down versions: ~15 minutes each after the master is done.

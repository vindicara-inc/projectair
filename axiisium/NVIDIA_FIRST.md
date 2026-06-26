# Axiisium — all-NVIDIA execution runbook

Strategy: run the entire build on NVIDIA's own platforms first. The deeper and longer we
live on NVIDIA infrastructure, the stronger the partnership and co-marketing position.
Move to Azure / Google only if we outgrow what NVIDIA provides.

Platform → stage map:

| Stage | NVIDIA platform | Cost |
|---|---|---|
| 1–4 (train the AML model, federated) | **DGX Cloud** (Inception $100K credits) or **DGX Cloud Innovation Lab** (2 months free) | credits / free |
| 5 (confidential computing attestation) | **NVIDIA LaunchPad** confidential-VM H100 lab | free |
| reasoning / report layer (Nemotron) | **build.nvidia.com** NIM endpoints | free |

---

## Part A — Applications (do these first; they have lead time)

1. **Refresh the Inception profile.** Benefits lapse if the profile is not updated every 6
   months. Log in to the Inception portal (NGC account), update company details, and
   re-save. A stale profile is the most common reason benefit requests go silent.
2. **Re-request DGX Cloud credits.** In the Inception portal benefits/offers section,
   request the **DGX Cloud credits** benefit (up to $100K). This is an in-portal request,
   not an email thread.
3. **Apply to the DGX Cloud Innovation Lab.**
   https://www.nvidia.com/en-us/data-center/dgx-cloud/innovation-lab/
   This is the 2-month hands-on access path for select Inception members and is the fastest
   dev-friendly way onto NVIDIA compute.
4. **(Backup only) Google + Azure credits.** Per the all-NVIDIA decision, leave these as
   fallback. The Inception + Google for Startups path (up to $350K GCP) is also requested
   inside the Inception portal, not by email; keep it warm but don't lead with it.

While these process, start Part B (free, today).

---

## Part B — Stage 5 on NVIDIA LaunchPad (free, start now)

The confidential-computing attestation needs no paid box. Use the free lab:

  **Build a Confidential VM with NVIDIA H100 Confidential Computing**
  https://www.nvidia.com/en-us/launchpad/ai/build-a-confidential-vm-with-nvidia-h100-confidential-computing/

In the lab you get a real SEV-SNP CVM + H100 in CC mode with the NVIDIA attestation flow
(NRAS). That is the real version of Stage 5's `SimulatedPlatform`. There you can:
- enable GPU CC mode and run the NVIDIA Attestation SDK / nvtrust flow,
- generate the ledger signing key inside the enclave,
- bind {enclave measurement, code hash, signing pubkey} for real,
- verify the quote through NRAS.

This validates the moat's hardware root on genuine NVIDIA silicon, at zero cost.

---

## Part C — Portable run commands (DGX Cloud / Innovation Lab / any NVIDIA GPU box)

These are identical on any NVIDIA GPU Linux env. Once you have a DGX Cloud node:

```bash
# 0. get the code onto the box (scp the axiisium folder up, or git clone your repo)
#    e.g. from your laptop:  rsync -avz axiisium/ user@dgx:~/axiisium/
cd ~/axiisium

# 1. environment
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install numpy cryptography Pillow            # Stage 0/dry deps
pip install torch monai timm                     # Stage 1 real encoder (GPU)

# 2. DinoBloom weights (hematology cell foundation model)
git clone https://github.com/marrlab/DinoBloom    # follow its README to fetch the ViT ckpt
#    place the checkpoint path, e.g. ~/weights/dinobloom_vitb14.pth

# 3. data — TCIA AML-Cytomorphology_LMU
#    Headless boxes have no browser for Aspera Connect. Two options:
#    (a) easiest: download via Aspera Connect on any machine with a browser, then
#        rsync the unzipped folder up:  rsync -avz AML-Cytomorphology_LMU/ user@dgx:~/data/
#    (b) IBM Aspera CLI (ascp) on the box if you have the TCIA connection details.
#    Also grab the two small direct files (no Aspera):
#        the Annotations (DAT+ZIP) and Abbreviations (TXT) from the TCIA page.
ls ~/data/AML-Cytomorphology_LMU/                 # confirm folder-per-class layout + blast names

# 4. RUN — real Stage 1 on GPU
python stage1.py \
  --data ~/data/AML-Cytomorphology_LMU \
  --device cuda \
  --weights ~/weights/dinobloom_vitb14.pth
#  target: blast-detection AUC >= 0.95, NPM1 image-only ~0.90

# 5. the rest of the stack (these already run; on real data swap the synthetic cohorts)
python stage2.py        # multimodal mutation prediction
python stage3.py        # federated (port to NVIDIA FLARE per stage3/README for real nodes)
python run_all.py       # full sweep, every stage signed
```

Federated for real (Stage 3): `pip install nvflare` and follow `stage3/README.md` to wrap
`LogisticModel.local_train` as a FLARE Executor + FedAvg Controller, then
`nvflare simulator -n 3 -t 3 <job>`.

---

## Part D — Reasoning layer (free, when you wire it in)

NVIDIA NIM endpoints at https://build.nvidia.com give free Nemotron inference for the
agent/report step (the Stage 0 "reasoning" layer). Call them from the pipeline once the
core model is proven; no GPU needed for this part.

---

## Sequencing (what to do, in order)

1. **Today:** refresh Inception profile, re-request DGX Cloud credits, apply to Innovation
   Lab (Part A). Start the LaunchPad confidential-VM lab for Stage 5 (Part B).
2. **On DGX Cloud access:** run real Stage 1 (Part C). Get the feasibility number.
3. **Then:** Stage 2 on any real paired data you source; Stage 3 federated via FLARE;
   Stage 5 validated on LaunchPad; reasoning via NIM.
4. **Only if you outgrow NVIDIA:** fall back to the Azure confidential box or GCP A3.

The whole stack stays on NVIDIA silicon end to end, which is exactly the partnership
position we want before the co-marketing and specialization conversations.

#!/usr/bin/env python3
"""
AIR Denials Demo - prior-authorization appeal agent with a REAL signed, verifiable evidence record.

What is real here: every agent action is signed with Ed25519, hash-chained to the previous
action, bound to a named clinician, and verifiable. Change one byte and verification fails.
That is the moat (FRE 902(13)/(14) self-authenticating record), and it runs for real below.

What is a stub here: the clinical reasoning is deterministic rule-matching on the sample data.
In production this step is NVIDIA Nemotron on NIM, with NeMoGuard catching hallucinations, all
inside NVIDIA Confidential Computing so PHI never leaves an attested enclave.
"""
import hashlib, json, copy
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64

class SignedChain:
    """The substrate: signed-at-the-moment-of-action, hash-chained, externally verifiable."""
    def __init__(self):
        self._key = Ed25519PrivateKey.generate()
        self.pubkey_hex = self._key.public_key().public_bytes_raw().hex()
        self.records = []

    def record(self, kind, payload, human_authority=None):
        body = {
            "ordinal": len(self.records),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "payload": payload,
            "human_authority": human_authority,
            "prev_hash": self.records[-1]["content_hash"] if self.records else GENESIS,
        }
        content = json.dumps(body, sort_keys=True).encode()
        content_hash = hashlib.sha256(content).hexdigest()          # BLAKE3 in production
        signature = self._key.sign(bytes.fromhex(content_hash)).hex()  # Ed25519, real
        rec = {**body, "content_hash": content_hash, "signature": signature, "algorithm": "Ed25519"}
        self.records.append(rec)
        return rec

    @staticmethod
    def verify(records, pubkey_hex):
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        prev = GENESIS
        for r in records:
            body = {k: r[k] for k in ("ordinal", "timestamp", "kind", "payload", "human_authority", "prev_hash")}
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != r["content_hash"]:
                return False, f"content tampered at record #{r['ordinal']} ({r['kind']})"
            if r["prev_hash"] != prev:
                return False, f"broken chain link at record #{r['ordinal']}"
            try:
                pub.verify(bytes.fromhex(r["signature"]), bytes.fromhex(r["content_hash"]))
            except Exception:
                return False, f"invalid signature at record #{r['ordinal']}"
            prev = r["content_hash"]
        return True, "intact"


# ---- sample inputs: a messy clinical note + a real-shaped payer denial ----
CLINICAL_NOTE = """
PT: 54F. CC: chronic low back pain, radiating L leg, 5 months.
Hx: failed conservative care - 8 wks PT (notes 03/12-05/04), NSAIDs (naproxen) x6wks no relief,
    epidural steroid injection 04/22 transient relief only. Positive straight-leg raise left.
Exam: decreased sensation L5 dermatome, 4/5 EHL strength left.
Plan: MRI lumbar spine w/o contrast to eval for nerve root compression prior to surgical consult.
Prior imaging: XR lumbar 02/2026 - mild DDD, no acute finding.
""".strip()

DENIAL = {
    "payer": "Sample MA Plan",
    "service": "MRI lumbar spine without contrast (CPT 72148)",
    "criteria_set": "MCG / InterQual - imaging for low back pain",
    "reason": "Insufficient documentation of failed conservative treatment (>=6 weeks) prior to advanced imaging.",
    "required_criteria": [
        "Documented conservative therapy >= 6 weeks (PT and/or pharmacologic)",
        "Documented neurologic deficit OR red-flag findings",
        "Prior plain imaging when indicated",
    ],
}


# ---- the agent (reasoning stub; NVIDIA Nemotron + NeMoGuard go here in prod) ----
def extract_facts(note):
    facts = []
    if "8 wks PT" in note or "PT (" in note: facts.append(("conservative_therapy_PT", "8 weeks PT, 03/12-05/04"))
    if "NSAIDs" in note: facts.append(("conservative_therapy_pharm", "naproxen x6wks, no relief"))
    if "epidural steroid injection" in note: facts.append(("interventional", "ESI 04/22, transient relief"))
    if "decreased sensation" in note or "straight-leg raise" in note:
        facts.append(("neuro_deficit", "L5 dermatome sensory loss, 4/5 EHL, +SLR left"))
    if "XR lumbar" in note: facts.append(("prior_imaging", "XR lumbar 02/2026, mild DDD"))
    return facts

def match_criteria(facts, denial):
    have = {k for k, _ in facts}
    met, missing = [], []
    if {"conservative_therapy_PT", "conservative_therapy_pharm"} & have:
        met.append(("Documented conservative therapy >= 6 weeks", "8wk PT + 6wk NSAIDs = exceeds 6 weeks"))
    else:
        missing.append("Conservative therapy >= 6 weeks")
    if "neuro_deficit" in have:
        met.append(("Documented neurologic deficit", "L5 sensory loss, 4/5 EHL, +SLR"))
    else:
        missing.append("Neurologic deficit")
    if "prior_imaging" in have:
        met.append(("Prior plain imaging", "XR lumbar 02/2026"))
    return met, missing

def draft_appeal(facts, met, denial):
    lines = [
        f"RE: Appeal of denial - {denial['service']}",
        f"Payer: {denial['payer']}   Criteria: {denial['criteria_set']}",
        "",
        "The denial cites insufficient documentation of failed conservative treatment. The clinical",
        "record submitted herewith demonstrates that every required criterion was, in fact, met at the",
        "time of the request. The documentation was present in the chart and is itemized below:",
        "",
    ]
    for crit, evidence in met:
        lines.append(f"  - {crit}: {evidence}")
    lines += [
        "",
        "This satisfies the MCG/InterQual threshold for advanced lumbar imaging. We respectfully",
        "request the denial be overturned and the MRI authorized.",
    ]
    return "\n".join(lines)


def run():
    chain = SignedChain()
    bar = "=" * 74
    print(bar); print("AIR DENIALS DEMO  -  prior-auth appeal agent + signed evidence record"); print(bar)

    chain.record("denial_ingested", {"payer": DENIAL["payer"], "service": DENIAL["service"],
                                      "reason": DENIAL["reason"]})
    facts = extract_facts(CLINICAL_NOTE)
    chain.record("clinical_facts_extracted", {"facts": facts, "engine": "stub (prod: NVIDIA Nemotron on NIM)"})
    met, missing = match_criteria(facts, DENIAL)
    chain.record("criteria_matched", {"met": [m[0] for m in met], "missing_at_initial_review": missing,
                                       "finding": "criteria were met; documentation was simply not submitted"})
    clinician = "Dr. A. Rivera, MD  (NPI 1234567890)"
    appeal = draft_appeal(facts, met, DENIAL)
    chain.record("appeal_generated",
                 {"appeal_sha256": hashlib.sha256(appeal.encode()).hexdigest(),
                  "criteria_satisfied": len(met)},
                 human_authority=clinician)
    chain.record("sealed", {"anchor": "Sigstore Rekor (simulated in demo)",
                            "records": len(chain.records) + 1})

    print("\n--- GENERATED APPEAL LETTER (Product A: the money) ---\n")
    print(appeal)

    print("\n--- SIGNED EVIDENCE PACKET (Product B: the moat) ---")
    print(f"  Records          : {len(chain.records)} (each Ed25519-signed, hash-chained)")
    print(f"  Decision by      : {clinician}  <- human accountability (answers nH Predict)")
    print(f"  Chain root       : {chain.records[-1]['content_hash'][:48]}...")
    print(f"  Public key       : {chain.pubkey_hex[:48]}...")

    ok, msg = SignedChain.verify(chain.records, chain.pubkey_hex)
    print(f"\n  VERIFY (clean)   : {'VALID' if ok else 'FAIL'} - chain {msg}")

    # tamper demo: a payer/auditor cannot quietly alter the record after the fact
    tampered = copy.deepcopy(chain.records)
    tampered[3]["human_authority"] = "(removed - pretend no clinician reviewed it)"
    ok2, msg2 = SignedChain.verify(tampered, chain.pubkey_hex)
    print(f"  VERIFY (tampered): {'VALID' if ok2 else 'TAMPER DETECTED'} - {msg2}")

    out = {"appeal": appeal, "pubkey": chain.pubkey_hex, "records": chain.records}
    with open("evidence_packet.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\n  evidence_packet.json written (independently verifiable, zero vendor calls)")
    print("\n" + bar)
    print("A writable audit log cannot prove what a tamper-evident, externally-keyed chain proves.")
    print("That is FRE 902(13)/(14). Reasoning -> NVIDIA Nemotron/NeMoGuard. PHI -> Confidential Computing.")
    print(bar)


if __name__ == "__main__":
    run()

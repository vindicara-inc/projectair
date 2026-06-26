# Axiisium Stage 5 — confidential computing (hardware-to-application trust)

The final link. Stages 0–4 prove *what* was computed and *by whose authority* (signed
ledgers). Stage 5 proves those records were produced by the *expected code* running inside
*genuine confidential hardware* — so nothing was substituted between the silicon and the
signed result.

## The gap it closes (NVIDIA names it themselves)

From NVIDIA FLARE's confidential-computing docs, verbatim:

> *"Without proper design of the Confidential VM (CVM) to extend the chain of trust from
> hardware to the application workload, confidential computing attestation will NOT be able
> to detect deployment-time code modifications or tampering."*

Attestation proves the enclave is genuine. It does **not**, by itself, prove what code ran
or bind that to the records the code produced. Stage 5 binds three things into one
platform-signed object:

1. **enclave measurement** — genuine TEE (AMD SEV-SNP / Intel TDX) + NVIDIA GPU CC
2. **code measurement** — hash of the exact pipeline source that executed
3. **signing public key** — the key every Stage 0–4 ledger is signed with

A verifier then proves end to end: *these signed records came from this code, in a real
enclave, with nothing swapped.*

## Run

```bash
python ../stage5.py
```

Shows the clean chain verifying, then three attacks each blocked:

```
VERIFY (clean)            : VALID  - hardware -> code -> signing-key chain intact
ATTACK 1 (code modified)  : BLOCKED - code measurement mismatch
ATTACK 2 (key substituted): BLOCKED - signing key not bound to this enclave
ATTACK 3 (forged enclave) : BLOCKED - untrusted attestation platform key
```

## Production mapping (NVIDIA Confidential Computing)

| Stage 5 reference | Production |
|---|---|
| `SimulatedPlatform` | AMD SEV-SNP / Intel TDX CPU quote + NVIDIA GPU attestation |
| `platform_pubkey` trust check | verification via the **NVIDIA Remote Attestation Service (NRAS)** + CPU vendor root |
| `enclave_measurement` | the real launch measurement in the TEE quote |
| `code_measurement` | measured boot / container digest of the deployed pipeline image |
| signing key "generated in enclave" | key sealed to the enclave, never exported |
| `verify_attestation` | a relying party (sponsor / regulator / peer site) checking the quote |

Steps:
1. Run the Stage 1–4 pipeline inside a Confidential VM with NVIDIA GPU CC enabled.
2. Generate the ledger signing key **inside** the enclave; never export it.
3. On each run, obtain the platform quote, bind {enclave measurement, code/container
   digest, signing pubkey}, and publish the attestation alongside the signed ledger.
4. Verifiers check the quote through NRAS + the CPU vendor, then confirm the code digest
   and signing key match expectations.

## Where this lands in the stack

Combined with Stage 3, this is the complete trust contract:

> **NVIDIA Confidential Computing (hardware root of trust) + Axiisium (application-layer
> signed chain of custody, bound to the attested enclave) = provably private, provably
> untampered, provably authorized, attributable — from the chip to the clinical result.**

That is the end-to-end guarantee a regulator and a pharma sponsor need, and the exact thing
no image-only model and no plain FLARE deployment provides.

## Honest limits

- This simulates the platform quote. The real security rests on the genuine TEE + NRAS
  verification; the binding logic here is faithful but the hardware root must be real.
- Measured-boot / container-digest discipline is an engineering effort (reproducible
  builds, pinned images). The guarantee is only as strong as the measurement is precise.

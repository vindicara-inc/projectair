"""Vindicara ops chain. Vindicara dogfoods AIR for its own production audit trail.

Each Lambda invocation and dashboard auth event produces a short signed AgDR
chain via airsdk.AIRRecorder. Records land in DynamoDB; a separate cron Lambda
batches and anchors them to public Sigstore Rekor; a publisher cron Lambda
writes redacted JSONL into a public S3 bucket. The chain catalog is verifiable
end-to-end via `air verify-public`.

The trust contract matches customer chains exactly: signatures bind to the
moment of action, in-process, with the recorder's key. Anchoring is async.
"""

/**
 * Ed25519 verification — mirrors python `cryptography` Ed25519PublicKey.verify.
 *
 * Wire format (matches packages/projectair/src/airsdk/agdr.py):
 * - signer_key: 32-byte raw public key, hex-encoded (64 hex chars)
 * - signature: 64-byte raw Ed25519 signature, hex-encoded (128 hex chars)
 * - signed material: bytes.fromhex(prev_hash) + bytes.fromhex(content_hash)
 *   = exactly 128 raw bytes (64 + 64)
 */

import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';

export function verifySignature(args: {
	signatureHex: string;
	signerKeyHex: string;
	prevHash: string;
	contentHash: string;
}): boolean {
	const signature = hexToBytes(args.signatureHex);
	const publicKey = hexToBytes(args.signerKeyHex);
	const prev = hexToBytes(args.prevHash);
	const content = hexToBytes(args.contentHash);
	const message = new Uint8Array(prev.length + content.length);
	message.set(prev, 0);
	message.set(content, prev.length);
	try {
		return ed25519.verify(signature, message, publicKey);
	} catch {
		return false;
	}
}

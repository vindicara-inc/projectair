/**
 * BLAKE3 wrapper — default 256-bit (64 hex chars) digest.
 *
 * Mirrors packages/projectair/src/airsdk/agdr.py:63-64
 *   def _blake3_hex(data: bytes) -> str:
 *       return blake3.blake3(data).hexdigest()
 */

import { blake3 } from '@noble/hashes/blake3';
import { bytesToHex } from '@noble/hashes/utils';

export function blake3Hex(data: Uint8Array): string {
	return bytesToHex(blake3(data));
}

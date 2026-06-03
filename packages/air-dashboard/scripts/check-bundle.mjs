#!/usr/bin/env node
/**
 * Bundle budget enforcement for the AIR HUD.
 *
 * Hard limits per the approved plan:
 *   - INITIAL_LIMIT_KB: total JS the browser fetches before any user action.
 *     Lazy chunks (Three.js, dynamically imported scene module) are excluded.
 *   - TOTAL_LIMIT_KB: every JS chunk shipped, summed.
 *
 * Heuristic for "initial vs lazy": chunks larger than LAZY_THRESHOLD_KB are
 * assumed to be the dynamically-imported Three.js bundle (or future heavy
 * lazy deps). This is correct for Phase 0 because the only big lazy chunk we
 * ship is the scene module + its three transitive dep.
 *
 * Run AFTER `npm run build`. Exits nonzero if any limit is breached.
 */

import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = join(fileURLToPath(import.meta.url), '..', '..');
const BUILD_IMMUTABLE = join(PACKAGE_ROOT, 'build', '_app', 'immutable');

const INITIAL_LIMIT_KB = 420;
const TOTAL_LIMIT_KB = 930;
const LAZY_THRESHOLD_KB = 200;

function walkJs(dir) {
	const out = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			out.push(...walkJs(full));
		} else if (entry.isFile() && entry.name.endsWith('.js')) {
			out.push({ path: full, sizeBytes: statSync(full).size });
		}
	}
	return out;
}

let exitCode = 0;
try {
	const chunks = walkJs(BUILD_IMMUTABLE).sort((a, b) => b.sizeBytes - a.sizeBytes);
	if (chunks.length === 0) {
		console.error(`no chunks found under ${BUILD_IMMUTABLE} — did you run \`npm run build\`?`);
		process.exit(2);
	}

	const totalBytes = chunks.reduce((sum, c) => sum + c.sizeBytes, 0);
	const lazyBytes = chunks
		.filter((c) => c.sizeBytes > LAZY_THRESHOLD_KB * 1024)
		.reduce((sum, c) => sum + c.sizeBytes, 0);
	const initialBytes = totalBytes - lazyBytes;

	const totalKb = totalBytes / 1024;
	const initialKb = initialBytes / 1024;
	const lazyKb = lazyBytes / 1024;

	console.log('AIR HUD bundle audit');
	console.log('────────────────────────────────────');
	console.log(`Total JS    : ${totalKb.toFixed(1).padStart(7)} KB / ${TOTAL_LIMIT_KB} KB limit`);
	console.log(`Initial JS  : ${initialKb.toFixed(1).padStart(7)} KB / ${INITIAL_LIMIT_KB} KB limit`);
	console.log(`Lazy chunks : ${lazyKb.toFixed(1).padStart(7)} KB (>${LAZY_THRESHOLD_KB} KB; loaded on demand)`);
	console.log('');
	console.log('Top 10 chunks:');
	for (const c of chunks.slice(0, 10)) {
		const rel = c.path.slice(PACKAGE_ROOT.length + 1);
		const lazy = c.sizeBytes > LAZY_THRESHOLD_KB * 1024 ? '  (lazy)' : '';
		console.log(`  ${(c.sizeBytes / 1024).toFixed(1).padStart(7)} KB  ${rel}${lazy}`);
	}
	console.log('');

	if (initialKb > INITIAL_LIMIT_KB) {
		console.error(`✘ INITIAL JS over budget by ${(initialKb - INITIAL_LIMIT_KB).toFixed(1)} KB`);
		exitCode = 1;
	} else {
		console.log(`✓ initial JS under budget (${(INITIAL_LIMIT_KB - initialKb).toFixed(1)} KB headroom)`);
	}
	if (totalKb > TOTAL_LIMIT_KB) {
		console.error(`✘ TOTAL JS over budget by ${(totalKb - TOTAL_LIMIT_KB).toFixed(1)} KB`);
		exitCode = 1;
	} else {
		console.log(`✓ total JS under budget (${(TOTAL_LIMIT_KB - totalKb).toFixed(1)} KB headroom)`);
	}
} catch (cause) {
	console.error(`bundle audit failed: ${cause.message ?? cause}`);
	process.exit(2);
}

process.exit(exitCode);

/**
 * Deterministic geometric glyph from a BLAKE3 content hash.
 *
 * The same hash always produces the same glyph; different hashes produce
 * visibly different glyphs. Operators can scan a chain at a glance and see
 * that consecutive capsules carry distinct hashes (and that a tampered
 * capsule's recomputed hash produces a glyph that no longer matches the
 * stored content_hash glyph). Visual checksum.
 *
 * Construction: identicon-style 5×5 grid with horizontal mirror symmetry.
 * Cells (0,0)..(0,2), (1,0)..(1,2), ..., (4,0)..(4,2) are derived from the
 * first 8 bytes of the hash; cells (i,3) and (i,4) mirror (i,1) and (i,0).
 * Color comes from bytes 8..11 (foreground hue) holding hue/saturation in
 * the cyan-amber band so glyphs always read as HUD-native.
 */

const GRID_SIZE = 5;
const HALF_WIDTH = Math.ceil(GRID_SIZE / 2);

export interface GlyphOptions {
	pixel?: number;
	margin?: number;
	background?: string;
}

export function glyphSvg(contentHashHex: string, options: GlyphOptions = {}): string {
	const pixel = options.pixel ?? 8;
	const margin = options.margin ?? 1;
	const background = options.background ?? 'transparent';

	const bytes = bytesFromHex(contentHashHex.slice(0, 24));
	const fg = colorFromBytes(bytes[8] ?? 0, bytes[9] ?? 0, bytes[10] ?? 0);
	const accent = colorFromBytes(bytes[11] ?? 0, bytes[8] ?? 0, bytes[9] ?? 0);

	const cells = buildGrid(bytes);
	const sideCells = GRID_SIZE * pixel;
	const totalSize = sideCells + margin * 2 * pixel;
	const rects: string[] = [];

	for (let r = 0; r < GRID_SIZE; r++) {
		for (let c = 0; c < GRID_SIZE; c++) {
			if (!cells[r]![c]) continue;
			const x = margin * pixel + c * pixel;
			const y = margin * pixel + r * pixel;
			const fill = (r + c) % 3 === 0 ? accent : fg;
			rects.push(`<rect x="${x}" y="${y}" width="${pixel}" height="${pixel}" fill="${fill}" />`);
		}
	}

	return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalSize}" height="${totalSize}" viewBox="0 0 ${totalSize} ${totalSize}" shape-rendering="crispEdges">
<rect width="100%" height="100%" fill="${background}" />
${rects.join('\n')}
</svg>`;
}

function buildGrid(bytes: number[]): boolean[][] {
	const grid: boolean[][] = [];
	for (let r = 0; r < GRID_SIZE; r++) {
		const row: boolean[] = new Array(GRID_SIZE).fill(false);
		for (let c = 0; c < HALF_WIDTH; c++) {
			const bitIndex = r * HALF_WIDTH + c;
			const byte = bytes[Math.floor(bitIndex / 8) % bytes.length] ?? 0;
			const bit = (byte >> (bitIndex % 8)) & 1;
			row[c] = bit === 1;
			row[GRID_SIZE - 1 - c] = bit === 1;
		}
		grid.push(row);
	}
	return grid;
}

function bytesFromHex(hex: string): number[] {
	const out: number[] = [];
	const len = hex.length - (hex.length % 2);
	for (let i = 0; i < len; i += 2) {
		out.push(parseInt(hex.slice(i, i + 2), 16));
	}
	return out;
}

function colorFromBytes(b0: number, b1: number, b2: number): string {
	// Bias hues toward the HUD palette: cyan (180°) / amber (40°) / cool red (350°).
	// Pick one of three poles based on b0; perturb by b1 within ±15°.
	const poles = [180, 40, 350];
	const baseHue = poles[b0 % poles.length] ?? 180;
	const hue = (baseHue + ((b1 / 255) * 30 - 15) + 360) % 360;
	const saturation = 60 + (b2 % 30); // 60-89%
	const lightness = 55; // fixed for legibility on near-black background
	return `hsl(${hue.toFixed(1)},${saturation}%,${lightness}%)`;
}

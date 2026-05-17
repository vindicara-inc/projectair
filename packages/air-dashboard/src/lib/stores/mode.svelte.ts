/**
 * Mode store — TACTICAL accessibility mode auto-engages on
 *   - prefers-reduced-motion: reduce
 *   - viewport width < 768px
 * The 3D scene unmounts in TACTICAL; a mono table view takes its place.
 *
 * The store exposes both the resolved mode and the manual override; manual
 * override wins so an operator who explicitly enters TACTICAL on a desktop
 * stays there until they explicitly exit.
 */

export type Mode = 'cinematic' | 'tactical';

const TACTICAL_BREAKPOINT_PX = 768;

class ModeStore {
	manualOverride = $state<Mode | null>(null);
	autoTactical = $state(false);

	mode = $derived<Mode>(this.manualOverride ?? (this.autoTactical ? 'tactical' : 'cinematic'));

	bindMediaQueries(): () => void {
		if (typeof window === 'undefined') return () => {};
		const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
		const narrow = window.matchMedia(`(max-width: ${TACTICAL_BREAKPOINT_PX - 1}px)`);

		const update = (): void => {
			this.autoTactical = motion.matches || narrow.matches;
		};
		update();
		motion.addEventListener('change', update);
		narrow.addEventListener('change', update);
		return () => {
			motion.removeEventListener('change', update);
			narrow.removeEventListener('change', update);
		};
	}

	override(next: Mode | null): void {
		this.manualOverride = next;
	}
}

export const modeStore = new ModeStore();

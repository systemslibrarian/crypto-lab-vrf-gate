import { repeatedSquaring } from '../utils/vdfMath.js';

interface EvalMessage {
	g: bigint;
	N: bigint;
	T: number;
}

self.onmessage = (event: MessageEvent<EvalMessage>) => {
	try {
		const started = performance.now();
		const y = repeatedSquaring(event.data.g, event.data.N, event.data.T, (pct, squarings) => {
			self.postMessage({ type: 'progress', pct, squarings });
		});

		self.postMessage({
			type: 'done',
			y,
			timeMs: performance.now() - started,
			squarings: event.data.T,
		});
	} catch (error) {
		self.postMessage({
			type: 'error',
			message: error instanceof Error ? error.message : 'Unknown worker error',
		});
	}
};

export {};

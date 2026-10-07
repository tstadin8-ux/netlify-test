// Continual's health report and fixed menu for a Netlify Edge Function. MIT licence (c) 2026 GlueView Inc. Return
// continualGate(request, context) with what the edge function receives: undefined lets Netlify carry the request on; a
// Response is the maintenance page, or read-only mode's answer to a write, while a person has one on (each ends by itself
// within four hours). The check-in runs after the response through context.waitUntil, at most once per window in this
// copy, and never delays, changes or fails the request. It opens no route. Switch it all off with
// CONTINUAL_OPERATOR=off. The edge has no sockets: a database listed by its address reads "not checked here".
import declared from './continual.operator.json' with { type: 'json' };
import { KEYS } from './keys.mjs';
import { createOperator, toResponse } from './core.mjs';

const operator = createOperator({
  declared,
  keys: KEYS,
  env: (name) => globalThis.Netlify?.env?.get(name),
  // What only your code can answer, by the names continual.operator.json lists (see core.mjs, createOperator):
  // checks: { jobs: { 'nightly-import': async () => ({ last_run, ok }) }, queues: { emails: async () => count } },
  // The menu's hooks, by the names its `menu` lists (each runs only for what is listed there):
  // hooks: { features: { exports: { off: async () => {}, on: async () => {} } }, jobs: { 'nightly-import': async () => {} }, caches: { prices: async () => {} } },
});

/** The check-in alone, for an edge function that only reports. */
export function continualCheckIn(context) {
  const pending = operator.tick();
  if (typeof context?.waitUntil === 'function') context.waitUntil(pending);
}

/** The check-in, and the maintenance page or read-only answer while one is on: undefined to carry on. */
export function continualGate(request, context) {
  continualCheckIn(context);
  return toResponse(operator.hold({ method: request?.method, accept: request?.headers?.get?.('accept') }));
}

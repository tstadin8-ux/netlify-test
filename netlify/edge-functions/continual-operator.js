// Continual's health report rides this app's traffic (a Netlify Edge Function on every path). MIT licence (c) 2026
// GlueView Inc. It returns nothing, so Netlify carries every request on to the site as before, unless a person has put
// up the maintenance page or read-only mode, which end by themselves within four hours. After the response, at most once
// per window in this copy, the app checks in with Continual. Switch it all off with CONTINUAL_OPERATOR=off.
import { continualGate } from '../../continual-operator/netlify.mjs';

export default async (request, context) => continualGate(request, context);

export const config = { path: '/*' };

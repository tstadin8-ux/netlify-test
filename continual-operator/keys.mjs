// Continual's public keys for the health report. MIT licence (c) 2026 GlueView Inc.
// Continual signs each instruction with the private half of one of these, which stays in AWS KMS; core.mjs checks
// the signature with the public half. Nothing here is secret. A new key arrives by pull request, beside the old one,
// before Continual signs with it.
export const KEYS = [
  { kid: "lPttgrZg7LXHIqSi", spki: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERu1Bu+McmMJo1VADLZuLXLHGsF1rDvKAKLsszydAN+OZ2fVP6NZUy+GWpaTlkQtGK61em7W5k3O+EddWWUEMgg==" },
];

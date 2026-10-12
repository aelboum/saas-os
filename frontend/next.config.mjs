// Minimal foundation config -- no product/dashboard configuration yet.
// See docs/ADR/0011-backend-language-and-toolchain.md.
//
// Plain JavaScript on purpose: `next start` loads this file at runtime, and
// for a `next.config.ts` it needs the TypeScript compiler -- when that is
// missing it runs `npm install` for the development dependencies at
// container start. The runtime image has production dependencies only
// (frontend/Dockerfile), so the config must not need a compiler.

/** @type {import("next").NextConfig} */
const nextConfig = {};

export default nextConfig;

import { registerHooks } from 'node:module';

// Supervised orchestration fixtures use a fake CLI whose `sandbox` response is
// transport-only. Keep real platform/filesystem semantics while allowing those
// fixtures to exercise the historical macOS backend workflow on any host.
export function registerSupervisedMockSandboxBackend() {
  registerHooks({
    resolve(specifier, context, next) {
      if (specifier === './codex-sandbox.mjs' && context.parentURL?.endsWith('/src/agents/supervised-cloudflare.mjs')) {
        return { url: 'fixture:supervised-mock-sandbox-backend', shortCircuit: true };
      }
      return next(specifier, context);
    },
    load(url, context, next) {
      if (url === 'fixture:supervised-mock-sandbox-backend') {
        const original = new URL('../../src/agents/codex-sandbox.mjs', import.meta.url).href;
        const source = `export * from ${JSON.stringify(`${original}?supervised-mock-original`)};\n` +
          `import * as original from ${JSON.stringify(`${original}?supervised-mock-original`)};\n` +
          `export function assertSandboxBackend(version, platform = 'darwin') { return original.assertSandboxBackend(version, platform); }\n`;
        return { format: 'module', shortCircuit: true, source };
      }
      if (url.includes('?supervised-mock-original')) return next(url, context);
      return next(url, context);
    },
  });
}

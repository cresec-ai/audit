/**
 * Single source of truth for the tool version. Kept out of package.json so
 * every module mode (ESM import, CJS verify script, CLI banner) reads the
 * same constant without JSON-import interop tricks.
 */
export const VERSION = '0.1.0';
//# sourceMappingURL=version.js.map
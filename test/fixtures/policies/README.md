Sample policy.yaml v1 files used by `test/policy.test.ts` and `test/policy-rego.test.ts`; every file here is valid.
`expected/<name>/` holds the golden Rego bundle each one compiles to (regenerate with `UPDATE_GOLDENS=1 npx vitest run test/policy-rego.test.ts` and review the diff by eye).

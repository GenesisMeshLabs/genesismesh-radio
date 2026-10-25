# Repository instructions

This repository owns radio transport integration and constrained-device examples.
GenesisMesh authority, grant validation, and execution-evidence semantics stay in
the existing core and edge-agent projects. Consume their actual public APIs.

- Keep protocol, persistence, controller, and transport adapters in separate modules.
- Never treat a transport acknowledgment as confirmed device execution.
- Keep device identity, authenticated source claims, and bridge statements distinct.
- Never put operator credentials, radio keys, tokens, or runtime databases in Git.
- Tests generate disposable credentials and authorities; production is out of scope.
- The bridge permits verified decisions and bounded grants, never automatic break-glass.
- A missing, late, or ambiguous operation outcome must not become success.
- All changes go through a pull request; the maintainer merges.
- Use the configured personal identity and SSH-signed commits. No attribution trailers.
- Run lint, unit/property tests, packaging checks, firmware codec tests, and the
  disposable live integration suite when available. Report hardware tests separately.

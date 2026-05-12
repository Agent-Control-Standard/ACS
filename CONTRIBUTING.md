# Contributing to ACS

We're building trustworthy AI agents together. Your contributions make the future of agent observability and control possible.

**Before spending lots of time on something, ask for feedback on your idea first!**

Search existing issues and pull requests to avoid duplicating efforts.

## Code of Conduct

This project follows our [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## How to Contribute

**Ideas**: Join issue discussions or start new ones. Your voice shapes ACS direction.

**Writing**: Expand documentation with your expertise. Clear explanations help everyone.

**Copy Editing**: Fix typos, clarify language, improve quality. Every word matters. Follow our [styling guide](./STYLE.md).

**Code**: Implement specifications, build tools, create examples.

**Standards**: Help Improve ACS, extend CycloneDX, SPDX, SWID for agent components.

## Local Development

```bash
uv pip install -e .          # install dependencies
uv run mkdocs serve          # preview docs at http://localhost:8000
uv run mkdocs build          # build static docs
```

For prose contributions, follow the [editorial style guide](./STYLE.md). For schema contributions, validate `specification/ACS/acs_schema.json` against the JSON Schema spec before submitting.

All submissions go through GitHub pull request review. See [GitHub's PR guide](https://docs.github.com/en/pull-requests) if you're new to the workflow.

## Development Process

1. **Fork the repository** and clone your fork
2. **Create a feature branch** — use `feature/<short-description>` or `fix/<short-description>`
3. **Make your changes** following the style guide
4. **Sign your commits** with `git commit -s` (required by the DCO below)
5. **Open a pull request** against `main`
6. **Address review feedback** to land your change

For changes to the spec itself (`acs_schema.json`, hooks, events), open a [Discussion](https://github.com/Agent-Control-Standard/ACS/discussions) before submitting a PR — these affect downstream implementers and warrant a longer conversation.

## What We Need

**High Priority:**
Look for unassigned [Open Issues](https://github.com/Agent-Control-Standard/ACS/issues).

**Always Welcome:**
- Documentation improvements
- Real-world use case examples
- Security analysis and feedback
- Performance optimizations

## Release Process

Project maintainers handle formal releases. Focus on contributing great features and fixes.

## Reporting Security Issues

**Do not file public issues for security vulnerabilities.** Use GitHub's [private vulnerability reporting](https://github.com/Agent-Control-Standard/ACS/security/advisories/new) to disclose privately. We'll acknowledge within 72 hours and coordinate a fix and disclosure timeline with you.

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

- (a) The contribution was created in whole or in part by me and I have the right to
  submit it under the open source license indicated in the file; or

- (b) The contribution is based upon previous work that, to the best of my knowledge, is
  covered under an appropriate open source license and I have the right under that license
  to submit that work with modifications, whether created in whole or in part by me, under
  the same open source license (unless I am permitted to submit under a different
  license), as indicated in the file; or

- (c) The contribution was provided directly to me by some other person who certified
  (a), (b) or (c) and I have not modified it.

- (d) I understand and agree that this project and the contribution are public and that a
  record of the contribution (including all personal information I submit with it,
  including my sign-off) is maintained indefinitely and may be redistributed consistent
  with this project or the open source license(s) involved.

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE.txt) — the same license that covers the rest of the project.

This guide is based on [github-contributing](https://raw.githubusercontent.com/standard/.github/refs/heads/master/CONTRIBUTING.md).

## Community

- **[GitHub Discussions](https://github.com/Agent-Control-Standard/ACS/discussions)**: Ask questions, share ideas
- **[Issues](https://github.com/Agent-Control-Standard/ACS/issues)**: Report bugs, request features

We're building the future of AI agent observability and control. Join us.

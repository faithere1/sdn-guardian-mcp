# Contributing

Contributions are welcome. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

All contributions are released under the project's [Apache-2.0 license](LICENSE). By opening a
pull request or an issue you agree to that.

## Using the issue tracker

Use [GitHub Issues](https://github.com/faithere1/sdn-guardian-mcp/issues) for bug reports,
feature requests and questions. To pick up work, comment on an issue first so efforts don't
overlap. Good starting points are the items under
[Future work](README.md#future-work), for example a Colab T4 (4-bit) run or a run against a
real IOS-XE DevNet sandbox.

Report security problems privately, as described in [SECURITY.md](SECURITY.md), not in a public
issue.

## Changing the code

1. Fork the repo and create a branch.
2. Set up the dev environment:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -e ".[dev,live]"
   ```
3. Make the change. Keep these project rules:
   - Safety checks live in the server (`engine/`), never only in the prompt.
   - Tool outputs are compact Markdown, never raw JSON or YANG dumps.
   - New behavior comes with tests. Live-adapter tests use the simulated device, not real
     hardware.
4. Run the same checks as CI:
   ```bash
   .venv/bin/ruff check . && .venv/bin/pytest
   ```
5. Open a pull request that says what changed and why. If you reran the Colab notebook, add the
   run to [`docs/COLAB_VALIDATION.md`](docs/COLAB_VALIDATION.md).

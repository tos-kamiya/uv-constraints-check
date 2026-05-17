# uv-constraints-check

Check `uv.lock`, installed Python environments, or executable scripts against
GitHub Security Advisories data:
[GitHub Security Advisories](https://github.com/advisories).

## Prerequisites

- install the `security-constraints` command from
  [mam-dev/security-constraints](https://github.com/mam-dev/security-constraints)
  and make sure it is available in your `PATH`; this tool uses it to fetch the
  GitHub security advisory data
- `security-constraints` uses publicly available GitHub security advisory data, so a read-only GitHub token is sufficient
- a GitHub personal access token must be set in `SC_GITHUB_TOKEN`

Create the token in GitHub:

1. Sign in to GitHub and open `Settings` > `Developer settings`.
2. Open `Personal access tokens` > `Fine-grained tokens`, then click `Generate new token`.
3. Set a token name such as `security-constraints-read-only`.
4. Set `Repository access` to `Public Repositories (read-only)`.
5. Leave permissions as `No access`.
6. Click `Generate token` and copy the generated `github_pat_...` value.

Set the token in your shell:

```bash
export SC_GITHUB_TOKEN="github_pat_xxxxxxxxxxxxxxxxxxxxxxxx"
```

## Installation

```console
pipx install git+https://github.com/tos-kamiya/uv-constraints-check
```

## Usage

Check a lockfile:

```console
uv-constraints-check lockfile uv.lock
```

The command invokes `security-constraints --output -`, reads the generated
constraints from stdout, and checks the packages in the selected lockfile.
It also prints the lockfile, installed environment, or executable targets it is
checking.

To check packages installed in the current Python environment instead, use the
`installed` subcommand:

```console
uv-constraints-check installed
```

To inspect a different environment, pass its Python executable:

```console
uv-constraints-check installed --python /path/to/venv/bin/python
```

To scan Python scripts on `PATH` and inspect the environments they point to, use
the `executables` subcommand:

```console
uv-constraints-check executables
```

By default, this only scans executable scripts under your home directory.
Scripts that resolve to system interpreters outside your home directory are
skipped.

To scan every executable script on `PATH`, including system locations, add:

```console
uv-constraints-check executables --all-executables
```

`lockfile`, `installed`, and `executables` are mutually exclusive subcommands,
and one of them is required.

## License

`uv-constraints-check` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.

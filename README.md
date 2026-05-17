# uv-constraints-check

[![PyPI - Version](https://img.shields.io/pypi/v/uv-constraints-check.svg)](https://pypi.org/project/uv-constraints-check)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/uv-constraints-check.svg)](https://pypi.org/project/uv-constraints-check)

-----

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Installation

```console
pip install uv-constraints-check
```

## Usage

Run the checker from a directory that contains `uv.lock`:

```console
uv-constraints-check
```

The command invokes `security-constraints --output -`, reads the generated
constraints from stdout, and checks the packages in the current `uv.lock`.

## License

`uv-constraints-check` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.

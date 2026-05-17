# uv-constraints-check

[![PyPI - Version](https://img.shields.io/pypi/v/uv-constraints-check.svg)](https://pypi.org/project/uv-constraints-check)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/uv-constraints-check.svg)](https://pypi.org/project/uv-constraints-check)

-----

## 目次

- [前提条件](#前提条件)
- [インストール](#インストール)
- [使い方](#使い方)
- [ライセンス](#ライセンス)

## 前提条件

- `security-constraints` コマンドをインストールし、`PATH` 上で使えること
- GitHub の Personal Access Token を `SC_GITHUB_TOKEN` に設定していること

GitHub でトークンを作成します:

1. GitHub にサインインし、`Settings` > `Developer settings` を開きます。
2. `Personal access tokens` > `Fine-grained tokens` を開き、`Generate new token` をクリックします。
3. トークン名を `security-constraints-read-only` のように設定します。
4. `Repository access` を `Public Repositories (read-only)` に設定します。
5. `Permissions` はすべて `No access` のままにします。
6. `Generate token` をクリックし、生成された `github_pat_...` で始まる値をコピーします。

シェルでトークンを設定します:

```bash
export SC_GITHUB_TOKEN="github_pat_xxxxxxxxxxxxxxxxxxxxxxxx"
```

## インストール

```console
pipx install git+https://github.com/tos-kamiya/uv-constraints-check
```

## 使い方

ロックファイルをチェックする場合:

```console
uv-constraints-check lockfile uv.lock
```

このコマンドは `security-constraints --output -` を実行し、標準出力から生成された制約を読み取り、選択した lockfile に含まれるパッケージをチェックします。
また、チェック対象の lockfile・インストール済み環境・実行ファイルを表示します。

現在の Python 環境にインストール済みのパッケージをチェックするには、`installed` サブコマンドを使います:

```console
uv-constraints-check installed
```

別の環境を見たい場合は、その Python 実行ファイルを `--python` で指定します:

```console
uv-constraints-check installed --python /path/to/venv/bin/python
```

`PATH` 上の Python スクリプトを走査して、そこが指している環境をチェックするには `executables` サブコマンドを使います:

```console
uv-constraints-check executables
```

これは既定ではホームディレクトリ配下のスクリプトだけを走査します。
システム側の interpreter に解決されるものは除外されます。

`PATH` 上のすべての実行可能スクリプトを走査したい場合は `--all-executables` を付けます:

```console
uv-constraints-check executables --all-executables
```

`lockfile`、`installed`、`executables` は排他的なサブコマンドで、どれか一つが必須です。

## ライセンス

`uv-constraints-check` は [MIT](https://spdx.org/licenses/MIT.html) ライセンスの条件で配布されます。

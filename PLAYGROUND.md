# sealbox Playground

## Recommended environment: GitHub Codespaces

sealbox is a command-line security utility. A browser-based development environment is therefore more useful than a conventional web demo because the project needs:

- a real filesystem
- a local vault file
- standard input for password/fingerprint prompts
- multiple terminals
- two local TCP processes for secure sharing

GitHub Codespaces provides a browser-based VS Code environment backed by a remote VM and a configurable development container. A repository can supply `.devcontainer/devcontainer.json` to define that environment. urlGitHub Codespaces Python setuphttps://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/adding-a-dev-container-configuration/setting-up-your-python-project-for-codespaces

---

## Repository configuration

The repository contains:

```text
.devcontainer/devcontainer.json
```

The configuration uses a Python 3.14 development image and runs:

```bash
python3 -m unittest discover -s tests -q
```

after environment creation.

No project runtime package is installed.

---

## Creating the Codespace

After publishing the repository publicly on GitHub:

1. Open the repository.
2. Select **Code**.
3. Select **Codespaces**.
4. Create a codespace from the default branch.

GitHub also supports a direct creation URL:

```text
https://codespaces.new/OWNER/REPO-NAME
```

and a quick-start form:

```text
https://codespaces.new/OWNER/REPO-NAME?quickstart=1
```

GitHub documents both patterns and supports adding an “Open in GitHub Codespaces” badge to a README. urlCodespaces quick-creation linkshttps://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/setting-up-your-repository/facilitating-quick-creation-and-resumption-of-codespaces

Replace `OWNER/REPO-NAME` with the final public repository path before publishing the badge.

---

## First command

Once the Codespace opens:

```bash
python3 --version
python3 -m unittest discover -s tests -q
```

The test suite should report all tests passing.

Then:

```bash
python3 sealbox.py --help
```

---

## Run the complete demo

Follow [`DEMO.md`](DEMO.md).

The main interactive commands are:

```bash
python3 sealbox.py init
python3 sealbox.py add demo
python3 sealbox.py get demo
python3 sealbox.py ls
python3 sealbox.py verify
python3 sealbox.py totp code demo
python3 sealbox.py scan testdata/
python3 sealbox.py scan . --fail-on-findings
python3 sealbox.py bench --size 1 --iterations 3
```

---

## Two-terminal secure-share demo

Create two terminal sessions in the same Codespace.

Terminal A:

```bash
python3 sealbox.py share listen \
  --port 47821 \
  --confirm-fingerprint
```

Terminal B:

```bash
python3 sealbox.py share connect \
  127.0.0.1 47821 \
  "hello from sealbox" \
  --confirm-fingerprint
```

Because both processes run inside the same Codespace, `127.0.0.1` is sufficient.

---

## Runtime dependency boundary

The Codespaces environment is a development environment.

It is not part of:

```text
sealbox.py
build/sealbox.pyz
```

The runtime dependency boundary remains:

```text
Python standard library only
requirements.txt = empty
```

The Codespace may contain generic development tools provided by its base image. Those tools are not imported or invoked by sealbox at runtime.

GitHub documents that Codespaces environments are created from a dev container on a remote VM and can include common development tools. urlGitHub dev containershttps://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/adding-a-dev-container-configuration

---

## Cost and limits

GitHub provides included Codespaces usage for personal accounts, with quota measured in compute and storage. Current GitHub documentation lists monthly included usage for personal Free and Pro plans, with additional use subject to the account's billing configuration. urlGitHub Codespaces included usagehttps://docs.github.com/en/codespaces/troubleshooting/troubleshooting-included-usage

For a public demo, the safest practice is to let each visitor create their own Codespace rather than maintaining a long-running shared machine.

---

## Why not a hosted web wrapper?

A web wrapper would not reproduce the project's actual interface or security model well.

sealbox needs:

```text
filesystem
+
password prompts
+
raw TCP
+
multiple local processes
```

Codespaces preserves all four while showing the same source repository that is being reviewed.

---

## Recommended README badge

Once the final GitHub repository URL is known, add:

```markdown
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/OWNER/REPO-NAME?quickstart=1)
```

GitHub officially documents this badge pattern. urlGitHub Codespaces deep links and badgehttps://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/setting-up-your-repository/facilitating-quick-creation-and-resumption-of-codespaces

# Contributing to SupplyGraph

Thank you for your interest in SupplyGraph. This guide covers the development setup and the rules for contributions. For the domain basics (SBOM, PURL, VEX, regulations), see [docs/onboarding/DomainPrimer.md](docs/onboarding/DomainPrimer.md) (Japanese).

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md), not in public issues.

## 1. Before you start

- **Bugs and small fixes:** open a pull request, or an issue first if you are unsure.
- **Features and larger changes:** open an issue first and describe the goal, the input and the expected result. This saves rework.
- **Scope of this repository:** SupplyGraph is the industry-neutral core (L1). Industry-specific validation rules and regulatory workflows are built as separate apps on top of it, so the core stays free of them. If you are not sure where a change belongs, ask in an issue.

## 2. Developer Certificate of Origin (DCO)

All commits must be signed off. By signing off, you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change, or you otherwise have the right to submit it under the project's license (Apache-2.0).

Add the sign-off with `git commit -s`. It adds a line such as:

```
Signed-off-by: Your Name <you@example.com>
```

The name and email must match the commit author. A GitHub noreply address is fine. The DCO check on pull requests fails if a commit has no matching sign-off; fix it with `git rebase --signoff main` and force-push.

We do not ask for a contributor license agreement (CLA).

## 3. Requirements

| Item | Version |
| --- | --- |
| Frappe Framework | v16 (`version-16` branch) |
| Python | 3.14 |
| Node.js | 24 or later |
| MariaDB | 11.8 |
| Redis | included in the development containers |

We recommend the Dev Container of the official [frappe_docker](https://github.com/frappe/frappe_docker) (Docker + VS Code). Give Docker at least 4 GB of memory.

## 4. Setting up a development environment

### 4.1 Start the Dev Container

```shell
git clone https://github.com/frappe/frappe_docker.git
cd frappe_docker
cp -R devcontainer-example .devcontainer
cp -R development/vscode-example development/.vscode
```

Open the `frappe_docker` folder in VS Code and run "Dev Containers: Reopen in Container" from the command palette.

### 4.2 Create a bench and a site

Run the rest in the container terminal (user `frappe`). Check the versions first:

```shell
python3 --version   # 3.14.x
node --version      # v24 or later
```

If they differ, switch Node.js with `nvm install 24 && nvm use 24`, and Python with `PYENV_VERSION`.

```shell
cd development
bench init --skip-redis-config-generation --frappe-branch version-16 frappe-bench
cd frappe-bench

bench set-config -g db_host mariadb
bench set-config -g redis_cache redis://redis-cache:6379
bench set-config -g redis_queue redis://redis-queue:6379
bench set-config -g redis_socketio redis://redis-queue:6379

bench new-site supplygraph.localhost \
  --db-root-username root --db-root-password 123 \
  --mariadb-user-host-login-scope=% --admin-password admin

bench get-app https://github.com/lifegence/supplygraph.git
bench --site supplygraph.localhost install-app supplygraph
bench --site supplygraph.localhost set-config developer_mode 1
bench --site supplygraph.localhost set-config allow_tests true
bench use supplygraph.localhost
bench start
```

Open `http://supplygraph.localhost:8000` and log in as `Administrator` / `admin`.

To try the app with sample data, load the demo described in [docs/demo/DemoScenario.md](docs/demo/DemoScenario.md).

### 4.3 Enable pre-commit

```shell
cd apps/supplygraph
pre-commit install
```

ruff (Python), eslint and prettier (JavaScript) run on every commit.

## 5. Common commands

Run them in the `frappe-bench` directory.

| Purpose | Command |
| --- | --- |
| Start the development server | `bench start` |
| Apply DocType changes | `bench --site supplygraph.localhost migrate` |
| Run all tests of the app | `bench --site supplygraph.localhost run-tests --app supplygraph --test-category all` |
| Run the tests of one DocType | `bench --site supplygraph.localhost run-tests --doctype "SG Component" --test-category all` |
| Run one test module | `bench --site supplygraph.localhost run-tests --module supplygraph.sg_catalog.doctype.sg_component.test_sg_component --test-category all` |
| Python console | `bench --site supplygraph.localhost console` |
| Format and lint all files | `pre-commit run --all-files` (in `apps/supplygraph`) |

Frappe v16 runs unit tests (`UnitTestCase`) and integration tests (`IntegrationTestCase`) separately. Depending on the minor version, `run-tests` may run only unit tests by default and silently skip the integration tests. Always pass `--test-category all`.

## 6. Changing DocTypes

DocTypes are generated from `tools/doctype_spec.json` by `tools/gen_doctypes.py`. See [tools/README.md](tools/README.md).

- **Adding or changing fields:** edit `tools/doctype_spec.json`, then run `python3 tools/gen_doctypes.py`, `ruff format .` and `bench migrate`.
- **Edited in the Desk:** in developer mode, saving writes the JSON into the app. Make the same change in `doctype_spec.json`, or the next generator run overwrites it.
- **The generator overwrites files:** always review the result with `git diff`.
- **Workflows, Workspaces, Custom Fields:** export what you build in the Desk through `fixtures` in `hooks.py`.

## 7. Coding rules

- **Style:** Python is indented with tabs and follows ruff (line length 110). JavaScript follows prettier and eslint.
- **Naming:** DocType names start with `SG `. Field names and Select values are in English; the UI is translated through the locale files.
- **Dependencies:** the core depends on `frappe` only. Do not import `erpnext`; ERPNext integration belongs in a separate app. Write the license of any new library in the pull request; it must be compatible with Apache-2.0.
- **Large data and performance:** BOM entries and vulnerability matches are not child tables. Validation and matching of large SBOMs (thousands to tens of thousands of components) run in background jobs (`frappe.enqueue`), not in web requests. Prefer incremental processing to full scans.
- **External APIs:** mock OSV and other external APIs in tests, so that tests do not depend on the network.
- **Secrets:** never commit API keys or passwords. Use Password fields in `SG Settings` or `site_config.json`.
- **Tests:** add tests for new behavior (`IntegrationTestCase` where the database is involved). Write the test first and see it fail before it passes.
- **Translations:** user-facing strings must be translatable (`_()` in Python, `__()` in JavaScript). Japanese translations in `supplygraph/locale/ja.po` are welcome but not required.

## 8. Branches, commits and pull requests

- Work on a branch in your fork, for example `feat/12-osv-retry` or `fix/34-spdx-import`.
- Keep a pull request to one topic. Aim for about 400 lines or fewer, excluding generated files.
- **Commit messages:** the first line is an English imperative sentence that says what changed, for example `Retry OSV queries on HTTP 429`. Sign off every commit (see section 2).
- **Pull requests:** fill in the template and link the issue (`Closes #12`). Ask for a review after the tests and pre-commit pass.

## 9. Using AI coding agents

You may use AI coding agents. Please:

- read the generated code yourself and be able to explain it in the pull request;
- give the agent only this repository's code, public SBOMs and synthetic data — never customer data, secrets or API keys;
- make tests written by an agent fail once before they pass;
- not paste code from elsewhere without checking its license.

## 10. Definition of done

- The acceptance criteria of the issue are met and checked by tests.
- `run-tests` and `pre-commit` pass, and every commit is signed off.
- New or changed DocTypes and fields are reflected in `doctype_spec.json`.
- The pull request describes how to check the change by hand.

## 11. Language

Code, commit messages, pull requests and issues are in English. Issues and pull requests in Japanese are also welcome. Some documents under `docs/` are in Japanese for now.

## 12. License

SupplyGraph is licensed under the [Apache License 2.0](LICENSE). By contributing, you agree that your contributions are licensed under the same license.

# tools

DocType generator for the SupplyGraph core app.

| File | Purpose |
| --- | --- |
| `doctype_spec.json` | DocType definitions (fields, naming, kind, phase) |
| `gen_doctypes.py` | Generates DocType JSON / controller / test / JS files, `modules.txt` and `install.py` from the spec |

Settings that are not in the spec live at the top of `gen_doctypes.py`: module assignment, extra child tables, composite indexes, search indexes, title fields, DocTypes open to Data Import and role permissions.

## Usage

```bash
python3 tools/gen_doctypes.py   # writes into ./supplygraph
ruff format .                   # generator output is not pre-formatted
git diff                        # review before committing
```

## Caution

The generator **overwrites** the DocType files it produces. Once DocTypes are edited from the Desk (developer mode), either reflect those edits in `doctype_spec.json` first, or stop using the generator for that DocType. Always review `git diff` before committing.

DocType files are only added or overwritten, never deleted: if a DocType is removed from the spec, delete its folder manually.

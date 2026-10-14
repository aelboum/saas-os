# Consumer scaffold

A minimal starting point for a product built on SaaS OS (ADR-0039). Copy
this directory into a new repository; from then on every file is the
product's own (ADR-0015 rules 9-10) and SaaS OS does not track it.

It is not part of the `saas-os` package, is never imported by it, and is
not a product. The full walkthrough is `docs/CONSUMER-GUIDE.md`; every
code sample in that guide is taken from here.

## Use it

1. Copy this directory to a new repository.
2. Rename `my_product` everywhere: the directory, the imports, `SCHEMA`
   in `models.py`, `_SCHEMA` and the revision id in the migration, the
   permission resource in `permissions.py`, the job name in `jobs.py`, and
   the project name and package list in `pyproject.toml`. Keep them the
   same string.
3. Do not name a top-level package `saas_os`: that is the one import name
   the installed `saas-os` distribution owns (ADR-0038).
4. `pip install -e .`
5. Configure the environment (`docs/CONSUMER-GUIDE.md`, section 4) and
   create the restricted application database role (section 5).
6. `python -m my_product.migrate`
7. `uvicorn my_product.app:app` and `python -m my_product.worker`

## What it shows

| File | Shows |
|---|---|
| `pyproject.toml` | the single exact-SHA dependency on SaaS OS |
| `my_product/migrate.py` | SaaS OS's migrations, then the product's, then permission registration |
| `my_product/migrations/versions/0001_create_items_table.py` | a tenant-owned table: own schema, `tenant_id`, forced RLS, grants to the application role |
| `my_product/models.py`, `items.py` | tables and tenant-scoped data access without importing SQLAlchemy |
| `my_product/permissions.py` | declaring product permissions |
| `my_product/app.py`, `routes.py` | the application on `build_platform_app`, a route behind the ingress chain |
| `my_product/jobs.py`, `worker.py` | a tenant job, run on SaaS OS's production worker |
| `my_product/purge.py` | deleting product data when a tenant is purged |

## How it is tested

`tests/test_consumer_scaffold_integration.py` in the SaaS OS repository
builds a real wheel, installs it into an isolated virtual environment,
copies `my_product/` to a directory outside the repository and runs the
whole flow against a real PostgreSQL and Redis: both migration histories,
grants, forced RLS with a predicate-free query, the permission-gated
route with its denial cases, the job on a real worker, and tenant purge.
`tests/test_consumer_scaffold_unit.py` checks the structural rules
statically.

The pin in `pyproject.toml` is a real commit and is checked by
`tests/test_consumer_pins_unit.py`. It is `3677c86`, `main` after pull
request #21: the first published commit with ADR-0045's platform
authority complete, whose required `caller` on tenant lifecycle and
feature-flag functions the scaffold's code passes. It also has the
`saas_os` import root (ADR-0038), the worker's `extra_functions` seam
(ADR-0039) and the optional extras (ADR-0041). CI proves the scaffold against a
wheel built from the SaaS OS working tree; an install of the pin itself
is a recorded manual proof (`examples/reference-consumer/README.md`).
When you copy the scaffold, move the pin to the commit you reviewed.

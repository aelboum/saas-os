"""`my_product` -- the consumer scaffold (docs/CONSUMER-GUIDE.md).

A starting point for an independent product built on SaaS OS, copied once
into the product's own repository and owned by that product from then on
(ADR-0015 rules 9-10). It is not part of the `saas-os` package and is
never imported by it: the only dependency direction is
`my_product -> saas-os`.

Everything here reaches SaaS OS through the installed package's ordinary
imports (`api.*`, `core.*`, `infra.*`), never through a path into the
SaaS OS source tree.
"""

"""Modular AI security scanner framework.

Layout:
  engine/      test execution entry points (scan, CLI)
  tests/       vulnerability test-case catalogues (one subpackage per category)
  payloads/    attack signatures / payload data (JSON)
  evaluators/  turn observations into findings
  scoring/     risk-level, severity, and confidence derivation
  reporting/   normalized security findings
"""
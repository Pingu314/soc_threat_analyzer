# Changelog

  ## [1.0.0] - 2026-04-23
  ### Added
  - SIGMA-based detection rules: brute force (T1110.001), password spraying (T1110.003), impossible travel (T1078)
  - IP enrichment via ipinfo.io with in-memory caching
  - Risk scoring and severity labelling (HIGH/MEDIUM/LOW)
  - Alert deduplication across detection passes
  - CSV export and Flask REST dashboard at /alerts
  - 35 pytest tests

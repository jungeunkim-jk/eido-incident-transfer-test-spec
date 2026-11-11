# EIDO Incident Transfer Acceptance Test Specification, version 0.1

Test specification for the transfer of an active incident between two Public Safety Answering Points (PSAPs) using the NENA Emergency Incident Data Object (EIDO, NENA-STA-021.1a-2022) conveyed under NENA-STA-024.1.1-2025.

Status: version 0.1, draft for external review. Comments are welcome through the Issues tab of this repository.

Author: Jungeun Kim. Independent work; not a publication of the University of Florida.

## Contents

| File | Description |
|---|---|
| `C1_Test_Case_Specification_v0.1.pdf` | The specification: exchange under test (Part A), eleven test cases in three suites (Part B), results to date, limitations, and appendices |
| `scripts/eido_static_check_v1_1.py` | Level 1 static check: schema validation, rule checks R1 to R12, and mutation tests M1 to M10 |
| `scripts/make_fixtures.py` | Regenerates the two author-constructed fixtures (TD-02R and TD-02A) from the published NENA sample and checks their SHA-256 |
| `reports/TD-01_report_v1_1.txt`, `reports/TD-02R_report_v1_1.txt`, `reports/TD-02A_report_v1_1.txt` | Reports of the static checks executed on 8 November 2026 |

## What is not included

NENA standards, the NENA JSON schema, and the NENA sample files are not redistributed here. Obtain them from NENA:

* Schema and sample: https://github.com/NENA911/EIDO-JSON (commit 1ea5750 was used; `Schema/openapi.yaml` SHA-256 `33d7261c3b7ae73facfca18268c2774455e1167d2f7c3c627ebb62b5a5789512`)
* Standards: NENA-STA-021.1a-2022 and NENA-STA-024.1.1-2025, from nena.org

The fixtures TD-02R and TD-02A are derived from the NENA sample and are therefore not distributed. `make_fixtures.py` produces them byte for byte.

## Reproducing the results

Requires Python 3.9 or later and the packages `jsonschema` and `pyyaml`.

1. Download `Schema/openapi.yaml` and `Samples/Sample call transfer EIDO.json` from the NENA911/EIDO-JSON repository.
2. Regenerate the fixtures:

   ```
   python scripts/make_fixtures.py --sample "Sample call transfer EIDO.json" --outdir .
   ```

3. Run the static check on each fixture, for example:

   ```
   python scripts/eido_static_check_v1_1.py --schema openapi.yaml --sample "Sample call transfer EIDO.json" --operator "Your Name" --out TD-01_report.txt
   ```

The input hashes printed in each report identify the files that were checked. The reports in `reports/` omit the login and host name lines that the script also prints.

## Summary of results

Across ten deliberately introduced defects, validation against the published schema reported four. The other six (two registry values, a malformed timestamp, a location given both by value and by reference, an unresolved reference, and two owning agencies) were reported only by rule checks taken from the text of the standard. The Level 2 test cases, which need a live receiving system, have not been executed.

## Registry values

`eido_static_check_v1_1.py` contains the values of the NENA registries for agency role, incident type, location type, and incident status, taken from NENA-STA-021.1a-2022 for use in the rule checks. These values remain those of NENA.

## License

* Scripts: MIT License (see `LICENSE`).
* Specification document and reports: Creative Commons Attribution 4.0 International (CC BY 4.0).

## Citation

Kim, Jungeun. EIDO Incident Transfer Acceptance Test Specification, version 0.1. 2026. DOI: [to be added after archiving]

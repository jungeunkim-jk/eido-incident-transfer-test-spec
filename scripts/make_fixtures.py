#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regenerate the two author-constructed fixtures from the published NENA sample.

The fixtures are not distributed. Download "Sample call transfer EIDO.json" from the
NENA911/EIDO-JSON repository (https://github.com/NENA911/EIDO-JSON, folder Samples),
then run:

  python make_fixtures.py --sample "Sample call transfer EIDO.json" --outdir .

The script checks the SHA-256 of the input, applies the changes listed in Appendix B.1
of the specification, writes TD-02R_request_payload.json and
TD-02_author_constructed_incident_transfer.json (TD-02A), and checks their SHA-256
against the values recorded in the specification.

Requires Python 3.9 or later. No third-party packages.
"""
import argparse, hashlib, json, os, sys

SHA_TD01 = "4f98a553e6e095e25c96a377a068c18ea87fe1674c65199f9a2f7afe0d5bf57d"
SHA_TD02R = "c04a620e092a66a59d481b9799d8b2358f10b02cc96a41c5809aa4b24a601e58"
SHA_TD02A = "c49537b16b1e650d14b3fde55c200b36bc56f22e9fcc01d114540b79a7898ca2"

A_ID = "state.pa.us"                      # sending agency in the published sample
B_ID = "psap-b.example.org"               # synthetic receiving agency
SCENE_ID = "urn:emergency:uid:location:td02-incident-scene:example.org"
T_COMPONENT = "2021-04-30T14:44:00.000-04:00"
T_EIDO = "2021-04-30T14:45:00.000-04:00"


def build(sample_bytes, a_owner, b_owner, b_updated_by):
    d = json.loads(sample_bytes.decode("utf-8"))
    # 1. top-level update time, later than every component
    d["lastUpdateTimeStamp"] = T_EIDO
    # 2. owning indicator on the sending agency
    d["agencyComponent"][0]["incidentOwningAgencyIndicator"] = a_owner
    # 3. receiving agency
    d["agencyComponent"].append({
        "$id": B_ID,
        "lastUpdateTimeStamp": T_COMPONENT,
        "updatedByAgencyReference": {"$ref": b_updated_by},
        "agencyRoleDescriptionRegistryText": ["TransferredTo"],
        "agencyType": ["psap"],
        "incidentOwningAgencyIndicator": b_owner,
    })
    # 4. scene location; PIDF-LO copied from the sample's RoutingLocation entry
    d["locationComponent"].append({
        "$id": SCENE_ID,
        "lastUpdateTimeStamp": T_COMPONENT,
        "updatedByAgencyReference": {"$ref": A_ID},
        "locationTypeDescriptionRegistryText": "CurrentIncident",
        "locationByValue": d["locationComponent"][0]["locationByValue"],
    })
    # 5. incident component
    d["incidentComponent"] = {
        "$id": "urn:emergency:uid:incidentdata:td02-001:example.org",
        "lastUpdateTimeStamp": T_COMPONENT,
        "updatedByAgencyReference": {"$ref": A_ID},
        "incidentTypeCommonRegistryText": "MVA",
        "incidentStatusCommonRegistryText": ["Active"],
        "internalIncidentId": "TD02-A-0001",
        "locationReference": [{"$ref": SCENE_ID}],
    }
    return (json.dumps(d, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True, help="path of the unaltered NENA sample file")
    ap.add_argument("--outdir", default=".")
    a = ap.parse_args()
    raw = open(a.sample, "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != SHA_TD01:
        sys.exit("Input is not the expected sample.\n  expected %s\n  got      %s" % (SHA_TD01, got))
    ok = True
    for name, args, expected in (
        ("TD-02R_request_payload.json", (True, False, A_ID), SHA_TD02R),                           # request as sent
        ("TD-02_author_constructed_incident_transfer.json", (False, True, B_ID), SHA_TD02A),       # state after acceptance
    ):
        out = build(raw, *args)
        h = hashlib.sha256(out).hexdigest()
        with open(os.path.join(a.outdir, name), "wb") as f:
            f.write(out)
        match = (h == expected)
        ok = ok and match
        print("%-52s %s  %s" % (name, h, "matches the specification" if match else "DOES NOT MATCH"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EIDO static check v1.1 (Level 1, no network, no live system).

v1.1 changes (2026-11-08): R11 EIDO-IncidentType-Common registry (STA-021 section 3.2), M10 mutation,
  R12 size against the 10 MiB minimum recipient limit of STA-024 section 3.8.1 (513 Message Too Large),
  operator taken from --operator plus the OS login name instead of a fixed label.

What it does, on the three published files only:
  1. SHA-256 of each input file (so the record says which files were checked)
  2. JSON parse of the sample
  3. Schema validation of the sample against openapi.yaml -> EmergencyIncidentDataObjectType
  4. $id uniqueness and $ref resolution inside the EIDO
  5. Well-formedness of embedded XML strings (PIDF-LO, EmergencyCallData)
  6. Rules from the standard text that the schema does not enforce:
       - registry values (EIDO-AgencyRole, EIDO-LocationType, EIDO-IncidentStatus-Common)
       - RFC 3339 date-time form of timestamps
       - locationByValue XOR locationByReferenceUrl (NENA-STA-021 section 2.18)
       - additionalDataByValue XOR additionalDataByReferenceUrl (section 2.19)
       - at most one agency with incidentOwningAgencyIndicator = true (section 2.6)
       - incidentTypeCommonRegistryText in the EIDO-IncidentType-Common registry (section 3.2)
       - serialized size against the 10 MiB minimum recipient limit (STA-024 section 3.8.1, code 513)
  7. Mutation tests: deliberately broken copies of the sample, to show which
     defects the schema catches and which need a rule check.

Usage:
  python3 eido_static_check.py --schema openapi.yaml --sample "Sample call transfer EIDO.json" --operator "Your Name" --out report.txt

Requires: Python 3.9+, packages jsonschema and pyyaml
  pip install jsonschema pyyaml
"""
import argparse, copy, datetime, getpass, hashlib, json, platform, re, sys, warnings
from importlib.metadata import version as _ver
warnings.filterwarnings("ignore", category=DeprecationWarning)
import xml.etree.ElementTree as ET

try:
    import yaml
    import jsonschema
    from jsonschema import Draft7Validator
except ImportError as e:
    sys.exit("Missing package: %s. Run: pip install jsonschema pyyaml" % e.name)

# Registry values copied from NENA-STA-021.1a/1b text, sections 3.1, 3.2, 3.3, 3.8
AGENCY_ROLE = {"Assisting", "CallReceiving", "Dispatched", "Dispatching", "Informational", "TransferredTo"}
LOCATION_TYPE = {"RoutingLocation", "Caller", "CurrentIncident", "InitialIncident", "Investigation",
                 "Other", "Staging", "TowerLocation", "UnitLocation"}
INCIDENT_STATUS = {"Active", "Cancelled", "Closed", "FireUnderControl", "NewLocation", "ReOpened",
                   "ResourcesAssigned", "ResourcesEnroute", "ResourcesOnscene", "StructureCleared"}
INCIDENT_TYPE = {
    '911H', '911OPN', 'ABDOM', 'ABDUCTF', 'ABDUCTNF', 'ABUSE', 'ACCIND', 'ACTSHOOT', 'ADMIN', 'AIR',
    'AIRINC', 'ALIEN', 'ALLERGIC', 'ALMA', 'ALMB', 'ALMH', 'ALMR', 'ALRBA', 'ALRBOX', 'ALRBS',
    'ALRCO', 'ALRCO2', 'ALRDEFIB', 'ALRF', 'ALRGAS', 'ALRHEAT', 'ALRKPAD', 'ALRMED', 'ALRNGAS',
    'ALRPANA', 'ALRPANS', 'ALRPROPN', 'ALRPULL', 'ALRROBA', 'ALRROBS', 'ALRU', 'ALRVEH', 'ALRWTR',
    'ALS', 'ANIMAL', 'ASSAULT', 'ASSIST', 'ATL', 'BACK', 'BARICADE', 'BIO', 'BITE', 'BLDCLPSE',
    'BLEEDING', 'BLS', 'BOMB', 'BRGCLPSE', 'BURGLARY', 'BURN', 'CARDIAC', 'CARJACK', 'CDX',
    'CHEMICAL', 'CHESPAIN', 'CHOKE', 'CITASST', 'CIVDIS', 'CIVIL', 'CNTRFT', 'COURT', 'CRIMPS',
    'CRIMTRAF', 'CRWD', 'CU1', 'CU2', 'CU3', 'CURFEW', 'CUST', 'DEATH', 'DEATHNTF', 'DIABETIC',
    'DISORD', 'DISVEH', 'DMPX', 'DROWN', 'DRUGPAR', 'DRUGS', 'DUI', 'DVA', 'DVNA', 'EDP', 'ELEC',
    'ELECHZD', 'ELUDING', 'ENTRAP', 'ESCAPE', 'EXPLOS', 'EXPOSURE', 'EXTORT', 'EYE', 'FAIRC',
    'FALL', 'FAM', 'FAPT', 'FARSON', 'FAS', 'FASX', 'FBRUSH', 'FELEC', 'FFUEL', 'FIGHT', 'FIREWRKS',
    'FMARINE', 'FORCENTR', 'FOTHER', 'FRAUD', 'FREPORT', 'FSMOKE', 'FSTRU', 'FTRAILER', 'FTRAIN',
    'FTRASH', 'FTRUCK', 'FUNK', 'FVEH', 'GASLEAK', 'GASLEAKI', 'GASLEAKO', 'HARR', 'HATE', 'HAZ',
    'HAZMAT', 'HEADACHE', 'HEMRG', 'HLP1', 'HLP2', 'HOLD', 'HOMICIDE', 'HOSTAGE', 'IMP', 'INDECENT',
    'INFO', 'INTERNET', 'INTOX', 'INVEST', 'JUV', 'LARCENY', 'LIQUOR', 'MAJORINC', 'MAYDAY', 'MCI',
    'MISBOATR', 'MISCON', 'MNTL', 'MTLV', 'MVA', 'MVAHR', 'MVAINJY', 'MVAUNK', 'MVCP', 'NCIC',
    'NCRASLTWF', 'NCRCPRF', 'NCRELEV', 'NCRFACTR', 'NCRMUAIDF', 'NCRNDE', 'NCRNONE', 'NCRTASKFORCE',
    'NCRTESTF', 'NCRTRANS', 'NEGLECT', 'NOISE', 'NONEMERG', 'OD', 'ODOR', 'OPEN', 'ORDERV',
    'PANDEMIC', 'PARKING', 'PERFND', 'PERMISS', 'PERSUSP', 'PERUNCON', 'PERWANT', 'PHANDLE', 'PREG',
    'PROPFND', 'PROPLOST', 'PROPSTLN', 'PROW', 'PUBWKS', 'PURSUIT', 'RADIAT', 'RECKDRV', 'REPO',
    'RESCUE', 'RESIST', 'RESP', 'RESPARR', 'ROBBERY', 'RUNAWAY', 'SAR', 'SCH', 'SCRM', 'SEIZURE',
    'SEXOFFNS', 'SHOOT', 'SHOPLIFT', 'SICK', 'SLMP', 'SMOKING', 'SOL', 'STABBING', 'STDBY', 'STKX',
    'STROKE', 'SUBJSTP', 'SUICIDE', 'SUICTHRT', 'SUSP', 'TERROR', 'THAZ', 'THREATS', 'TOW', 'TRAIN',
    'TRAINDRL', 'TRANSFER', 'TRAUMA', 'TRAUMAP', 'TRESPASS', 'TROUBLE', 'TRUANT', 'TSTOP', 'VAG',
    'VANDAL', 'VEHABND', 'VEHASST', 'VEHLOCK', 'VEHREC', 'VEHSTLN', 'VEHSUSP', 'VICE', 'WARRANT',
    'WATER', 'WEAPON', 'WELFARE', 'WILDLIFE', 'WIRES', 'XTRICATE'}
TEN_MIB = 10 * 1024 * 1024  # STA-024 3.8.1: recipient maximum must be >= ten mebibytes
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def load_validator(schema_path):
    with open(schema_path, encoding="utf-8") as f:
        api = yaml.safe_load(f)
    root = {"$ref": "#/components/schemas/EmergencyIncidentDataObjectType", "components": api["components"]}
    # Resolver looks up '#/components/schemas/...' inside this document. External NIEM refs
    # (NIEMComponents/nc.yaml) are only followed if the instance contains ncPersonComponent
    # or ncVehicleComponent; the published sample does not.
    resolver = jsonschema.RefResolver(base_uri="", referrer=root)
    return Draft7Validator(root, resolver=resolver)

def schema_errors(validator, instance):
    errs = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    return ["/".join(str(p) for p in e.absolute_path) + ": " + e.message for e in errs]

def walk(obj, path=""):
    """yield (path, key, value) for every dict member"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield path, k, v
            yield from walk(v, path + "/" + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, path + "[%d]" % i)

def rule_checks(eido):
    out = []
    ids, refs, stamps, xmls = [], [], [], []
    for path, k, v in walk(eido):
        if k == "$id": ids.append((path, v))
        if k == "$ref": refs.append((path, v))
        if k in ("lastUpdateTimeStamp", "callStartTimestamp", "answerDate", "vehicleRelationshipTimeStamp", "eta"):
            stamps.append((path, v))
        if isinstance(v, str) and v.lstrip().startswith("<?xml"):
            xmls.append((path + "/" + k, v))
    idset = [v for _, v in ids]
    dup = {x for x in idset if idset.count(x) > 1}
    out.append(("R1 $id uniqueness", "PASS" if not dup else "FAIL", "%d ids, duplicates: %s" % (len(idset), sorted(dup) or "none")))
    unresolved = [(p, r) for p, r in refs if r not in idset]
    out.append(("R2 $ref resolution", "PASS" if not unresolved else "FAIL", "%d refs, unresolved: %s" % (len(refs), unresolved or "none")))
    bad_x = []
    for p, x in xmls:
        try: ET.fromstring(x)
        except ET.ParseError as e: bad_x.append((p, str(e)))
    out.append(("R3 embedded XML well-formed", "PASS" if not bad_x else "FAIL", "%d XML strings, failures: %s" % (len(xmls), bad_x or "none")))
    bad_t = [(p, v) for p, v in stamps if not (isinstance(v, str) and RFC3339.match(v))]
    out.append(("R4 RFC 3339 timestamps", "PASS" if not bad_t else "FAIL", "%d timestamps, malformed: %s" % (len(stamps), bad_t or "none")))
    bad_role = [a.get("$id") for a in eido.get("agencyComponent", []) if not set(a.get("agencyRoleDescriptionRegistryText", [])) <= AGENCY_ROLE]
    out.append(("R5 EIDO-AgencyRole registry", "PASS" if not bad_role else "FAIL", "agencies with values outside registry: %s" % (bad_role or "none")))
    bad_loc = [l.get("$id") for l in eido.get("locationComponent", []) if l.get("locationTypeDescriptionRegistryText") not in LOCATION_TYPE]
    out.append(("R6 EIDO-LocationType registry", "PASS" if not bad_loc else "FAIL", "locations with values outside registry: %s" % (bad_loc or "none")))
    inc = eido.get("incidentComponent")
    if inc:
        bad_st = [s for s in inc.get("incidentStatusCommonRegistryText", []) if s not in INCIDENT_STATUS]
        out.append(("R7 EIDO-IncidentStatus-Common registry", "PASS" if not bad_st else "FAIL", "values outside registry: %s" % (bad_st or "none")))
    else:
        out.append(("R7 EIDO-IncidentStatus-Common registry", "NA", "no incidentComponent in this EIDO"))
    both = [l.get("$id") for l in eido.get("locationComponent", []) if ("locationByValue" in l) == ("locationByReferenceUrl" in l)]
    out.append(("R8 location by value XOR by reference (2.18)", "PASS" if not both else "FAIL", "violations: %s" % (both or "none")))
    both2 = [a.get("$id") for a in eido.get("additionalDataComponent", []) if ("additionalDataByValue" in a) == ("additionalDataByReferenceUrl" in a)]
    out.append(("R9 additional data by value XOR by reference (2.19)", "PASS" if not both2 else "FAIL", "violations: %s" % (both2 or "none")))
    owners = [a.get("$id") for a in eido.get("agencyComponent", []) if a.get("incidentOwningAgencyIndicator") is True]
    out.append(("R10 at most one owning agency (2.6)", "PASS" if len(owners) <= 1 else "FAIL", "owners: %s" % (owners or "none")))
    if inc and "incidentTypeCommonRegistryText" in inc:
        t = inc.get("incidentTypeCommonRegistryText")
        out.append(("R11 EIDO-IncidentType-Common registry (3.2)", "PASS" if t in INCIDENT_TYPE else "FAIL", "value: %r" % t))
    else:
        out.append(("R11 EIDO-IncidentType-Common registry (3.2)", "NA", "no incidentComponent or no incident type in this EIDO"))
    size = len(json.dumps(eido, ensure_ascii=False).encode("utf-8"))
    out.append(("R12 size vs 10 MiB recipient minimum (STA-024 3.8.1)", "PASS" if size <= TEN_MIB else "FAIL", "%d bytes serialized" % size))
    return out

def mutations(sample):
    """Return list of (name, mutated instance, what should catch it)."""
    m = []
    x = copy.deepcopy(sample); x.pop("issuingElementIdentification", None)
    m.append(("M1 remove required issuingElementIdentification", x, "schema"))
    x = copy.deepcopy(sample); x["eidoVersion"] = "2.0"
    m.append(("M2 eidoVersion 2.0", x, "schema (enum)"))
    x = copy.deepcopy(sample); x["agencyComponent"][0].pop("agencyType", None)
    m.append(("M3 remove required agencyType", x, "schema"))
    x = copy.deepcopy(sample); x["agencyComponent"][0]["agencyRoleDescriptionRegistryText"] = ["Transferring"]
    m.append(("M4 agency role outside registry", x, "rule R5 (schema does not check registry values)"))
    x = copy.deepcopy(sample); x["lastUpdateTimeStamp"] = "04/30/2021 14:43"
    m.append(("M5 malformed top-level timestamp", x, "rule R4 (schema format: date-time is not enforced by default)"))
    x = copy.deepcopy(sample); x["locationComponent"][0]["locationByReferenceUrl"] = "https://example.invalid/loc"
    m.append(("M6 location with both by-value and by-reference", x, "rule R8 (schema does not enforce XOR)"))
    x = copy.deepcopy(sample); x["callComponent"][0]["agentReference"] = [{"$ref": "nobody@nowhere.example"}]
    m.append(("M7 dangling $ref", x, "rule R2"))
    x = copy.deepcopy(sample)
    a = copy.deepcopy(x["agencyComponent"][0]); a["$id"] = "county-b.example"; a["incidentOwningAgencyIndicator"] = True
    x["agencyComponent"][0]["incidentOwningAgencyIndicator"] = True; x["agencyComponent"].append(a)
    m.append(("M8 two owning agencies", x, "rule R10 (schema does not enforce single owner)"))
    x = copy.deepcopy(sample); x["callComponent"][0].pop("callStateRegistryText", None)
    m.append(("M9 remove required callStateRegistryText", x, "schema"))
    if "incidentComponent" in sample:
        x = copy.deepcopy(sample); x["incidentComponent"]["incidentTypeCommonRegistryText"] = "INVALID_CODE"
        m.append(("M10 incident type outside registry", x, "rule R11 (schema does not check registry values)"))
    return m

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True); ap.add_argument("--sample", required=True)
    ap.add_argument("--standard", help="optional: path of the standard .docx, hashed for the record")
    ap.add_argument("--out", default="eido_static_check_report.txt")
    ap.add_argument("--operator", required=True, help="name of the person running this check")
    a = ap.parse_args()
    L = []
    L.append("EIDO static check report (script v1.1)")
    L.append("Run at: " + datetime.datetime.now().astimezone().isoformat(timespec="seconds"))
    L.append("Operator: %s (OS login: %s; host: %s)" % (a.operator, getpass.getuser(), platform.node()))
    L.append("Python %s on %s; jsonschema %s; pyyaml %s" % (platform.python_version(), platform.platform(), _ver("jsonschema"), _ver("pyyaml")))
    L.append("")
    L.append("Input files (SHA-256):")
    for lab, p in (("schema", a.schema), ("sample", a.sample), ("standard", a.standard)):
        if p: L.append("  %-8s %s  %s" % (lab, sha256(p), p))
    L.append("")
    with open(a.sample, encoding="utf-8") as f:
        sample = json.load(f)
    L.append("1. JSON parse: PASS")
    v = load_validator(a.schema)
    errs = schema_errors(v, sample)
    L.append("2. Schema validation (EmergencyIncidentDataObjectType): %s" % ("PASS, 0 errors" if not errs else "FAIL, %d errors" % len(errs)))
    for e in errs: L.append("     " + e)
    L.append("3. Rule checks on the sample:")
    for name, res, detail in rule_checks(sample):
        L.append("   %-52s %-5s %s" % (name, res, detail))
    L.append("4. Mutation tests (each is a broken copy of the sample; a defect is 'detected' if the schema or a rule reports it):")
    for name, inst, expect in mutations(sample):
        se = schema_errors(v, inst)
        rc = [r for r in rule_checks(inst) if r[1] == "FAIL"]
        detected = bool(se) or bool(rc)
        how = ("schema: %d error(s)" % len(se) if se else "") + (" " if se and rc else "") + ("rules: %s" % ", ".join(r[0].split()[0] for r in rc) if rc else "")
        L.append("   %-52s %s  [%s]  expected: %s" % (name, "DETECTED" if detected else "NOT DETECTED", how or "none", expect))
    L.append("")
    L.append("Scope statement: this is a static check of published files on a single computer. No live system, network transport, authentication, or agency data was involved. It is not an execution of the test cases in the specification.")
    report = "\n".join(L)
    with open(a.out, "w", encoding="utf-8") as f: f.write(report + "\n")
    print(report)

if __name__ == "__main__":
    main()

"""SARIF 2.1.0 export of weaknesses, so code scanning UIs (GitHub, Azure DevOps, IDEs) can show
them inline. One rule per weakness kind with its CWE; results carry the evidence location and the
DFD elements they apply to."""
from collections import OrderedDict
from . import __version__
from .model import WEAKNESSES

LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "3.0", "info": "1.0"}


def to_sarif(ir, repo_url=None):
    kinds = sorted({w["kind"] for w in ir["weaknesses"]})
    rules = []
    for k in kinds:
        cwe, sev, stride, title = WEAKNESSES[k]
        rules.append(OrderedDict(id=f"c2d/{k}", name="".join(p.capitalize() for p in k.split("_")), shortDescription=OrderedDict(text=title),
                                 helpUri=f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",
                                 defaultConfiguration=OrderedDict(level=LEVEL[sev]),
                                 properties=OrderedDict(tags=["security", cwe, "STRIDE:" + "".join(stride)], **{"security-severity": SECURITY_SEVERITY[sev]})))
    names = {n["id"]: (n.get("name") or (f"{n['method']} {n['path']}" if "method" in n else n["id"])) for k in ("processes", "entities", "stores", "entry_points") for n in ir[k]}
    results = []
    for w in ir["weaknesses"]:
        ev = w["evidence"][0]
        results.append(OrderedDict(ruleId=f"c2d/{w['kind']}", ruleIndex=kinds.index(w["kind"]), level=LEVEL[w["severity"]],
                                   message=OrderedDict(text=f"{w['name']} ({w['cwe']}). Applies to: {', '.join(names.get(x, x) for x in w['applies_to'][:5])}."),
                                   locations=[OrderedDict(physicalLocation=OrderedDict(artifactLocation=OrderedDict(uri=ev["path"], uriBaseId="SRCROOT"),
                                                                                        region=OrderedDict(startLine=ev["start_line"], endLine=ev["end_line"])))],
                                   partialFingerprints=OrderedDict(c2dWeaknessId=w["id"]),
                                   properties=OrderedDict(dfdElements=list(w["applies_to"]), stride=list(w["stride"]))))
    return OrderedDict([("$schema", "https://json.schemastore.org/sarif-2.1.0.json"), ("version", "2.1.0"),
                        ("runs", [OrderedDict(tool=OrderedDict(driver=OrderedDict(name="code2design", version=__version__, informationUri="https://github.com/AskShri/code2designmapping", rules=rules)),
                                              originalUriBaseIds=OrderedDict(SRCROOT=OrderedDict(uri="file:///")),
                                              results=results,
                                              **({"versionControlProvenance": [OrderedDict(repositoryUri=repo_url, revisionId=ir["provenance"]["commit"])]} if repo_url else {}))])])

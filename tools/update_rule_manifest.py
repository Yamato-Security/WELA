"""Record exact extracted inputs; never invent an upstream revision for old data."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--rules-commit")
parser.add_argument("--generator-commit")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
corpus = root / "config/security_rules.json"
mapping = root / "config/eid_subcategory_mapping.csv"
data = json.loads(corpus.read_text(encoding="utf-8-sig"))
manifest = {
    "schemaVersion": 1,
    "corpusKind": "WELA extracted Hayabusa metadata; not complete upstream Sigma",
    "corpusSha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
    "mappingSha256": hashlib.sha256(mapping.read_bytes()).hexdigest(),
    "recordCount": len(data),
    "uniqueRuleCount": len({item["id"] for item in data}),
    "rulesRepository": "https://github.com/Yamato-Security/hayabusa-rules",
    "rulesCommit": args.rules_commit,
    "generatorRepository": "https://github.com/Yamato-Security/WELA-RulesGenerator",
    "generatorCommit": args.generator_commit,
    "metadataLimitations": ["Detection expressions and required fields are absent.", "Missing historical upstream revisions are unknown; file hashes pin the available inputs.", "Channel/EventID/GUID candidates do not prove native field support, outcomes, ingestion or query execution."],
}
(root / "config/rule_eligibility_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

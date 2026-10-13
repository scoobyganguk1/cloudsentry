# CloudSentry

**A local-first Terraform security scanner that turns risky cloud configuration into clear, actionable findings.**

CloudSentry checks Terraform `.tf` files for a focused set of common security footguns. It runs locally, needs no cloud account or credentials, and can produce both terminal output and a portable HTML report.

> **Status:** Portfolio project / early release. Rules are heuristic and intentionally scoped; review findings in context before changing infrastructure.

## See it in action

```console
$ python -m cloudsentry scan examples/insecure --format json
{
  "summary": {"critical": 1, "high": 2, "medium": 2, "low": 0, "total": 5},
  "findings": [
    {"rule_id": "CS-AWS-001", "severity": "CRITICAL", "file": "main.tf", "line": 6,
     "title": "S3 bucket allows public access", "resource": "aws_s3_bucket.public_assets"}
  ]
}
```

Run a report against the included intentionally vulnerable sample:

```bash
python -m cloudsentry scan examples/insecure --format html --output report.html
```

Then open `report.html` in a browser. The report is standalone and does not send configuration anywhere.

## Checks included

| Rule | Severity | What it looks for |
| --- | --- | --- |
| `CS-AWS-001` | Critical | Public-read ACL on an S3 bucket |
| `CS-AWS-002` | High | S3 bucket without an explicit public-access block |
| `CS-AWS-003` | High | Security group ingress open to the internet on a sensitive port |
| `CS-AWS-004` | Medium | EBS volume without encryption enabled |
| `CS-AWS-005` | High | RDS instance with storage encryption disabled |
| `CS-AWS-006` | Medium | CloudTrail without log file validation |

The scanner recognises simple Terraform resource blocks, comments, and quoted or unquoted scalar values. Complex expressions, modules, variables, and dynamic blocks can affect results; see [Limitations](#limitations).

## Install and use

Requires Python 3.10 or newer. There are no third-party dependencies.

```bash
git clone https://github.com/scoobyganguk1/cloudsentry.git
cd cloudsentry
python -m cloudsentry scan examples/insecure
python -m cloudsentry scan path/to/terraform --format html --output report.html
```

Use `--severity HIGH` to show only Critical and High findings, `--format json` for machine-readable output, and `--exclude-dir .terraform` to skip a directory. The CLI exits with status `1` when findings meet the selected severity threshold, `0` when no findings meet it, and `2` for usage or input errors.

## Design choices

- **Local-first:** source files stay on your machine; no credentials or network access are needed.
- **Explainable:** each finding includes a stable rule ID, source location, reason, and suggested remediation.
- **Useful output:** terminal output for a quick check, JSON for automation, and a self-contained HTML report for sharing.
- **Honest scope:** a small readable parser and explicit rules make the detection boundaries easy to inspect.

## Development

```bash
python -m unittest discover -s tests -v
python -m cloudsentry scan examples/insecure --format json
```

The test suite uses only Python's standard library. GitHub Actions runs it on pushes and pull requests.

## Limitations

CloudSentry is an educational static-analysis tool, not a replacement for Terraform validation, provider-aware policy engines, cloud configuration monitoring, or a security review. It parses a deliberately limited subset of HCL and may miss issues or produce false positives. It does not evaluate Terraform plans, remote state, variable values, module internals, or provider defaults. Never treat a clean scan as proof that infrastructure is secure.

## Roadmap

- [ ] Add rules for Azure and Google Cloud Terraform resources
- [ ] Add SARIF output for GitHub Code Scanning
- [ ] Improve expression and module-aware analysis
- [ ] Add configurable rule severity and exclusions

## Licence

MIT. See [LICENSE](LICENSE).


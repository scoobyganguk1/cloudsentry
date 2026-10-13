"""Small, dependency-free Terraform scanner with explicit heuristic rules."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SENSITIVE_PORTS = {22, 23, 3389, 3306, 5432, 1433, 27017, 6379}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    resource: str
    description: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Resource:
    kind: str
    name: str
    body: str
    start_line: int
    end_line: int


RESOURCE_START = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
BLOCK_START = re.compile(r'^\s*(?:resource|data|module|variable|output|provider|terraform)\b.*\{')


def _strip_comment(line: str) -> str:
    """Strip simple HCL line comments without treating markers in strings as comments."""
    quote = False
    escaped = False
    i = 0
    while i < len(line):
        char = line[i]
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif char == '"':
            quote = not quote
        elif not quote and (line.startswith("#", i) or line.startswith("//", i)):
            return line[:i]
        i += 1
    return line


def _brace_delta(line: str) -> int:
    quote = False
    escaped = False
    delta = 0
    for char in line:
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif char == '"':
            quote = not quote
        elif not quote:
            delta += (char == "{") - (char == "}")
    return delta


def parse_resources(source: str) -> list[Resource]:
    """Parse top-level resource blocks; nested braces are tracked, not interpreted."""
    resources: list[Resource] = []
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        clean = _strip_comment(lines[index])
        match = RESOURCE_START.match(clean)
        if not match:
            index += 1
            continue
        start = index
        depth = _brace_delta(clean)
        body_lines = [clean]
        index += 1
        while index < len(lines) and depth > 0:
            clean = _strip_comment(lines[index])
            depth += _brace_delta(clean)
            body_lines.append(clean)
            index += 1
        resources.append(Resource(match.group(1), match.group(2), "\n".join(body_lines), start + 1, index))
    return resources


def _attribute(resource: Resource, name: str) -> str | None:
    # Only match simple direct assignments, not attributes nested inside a block.
    depth = 0
    for line in resource.body.splitlines()[1:]:
        before = depth
        depth += _brace_delta(line)
        if before != 0:
            continue
        match = re.match(rf'^\s*{re.escape(name)}\s*=\s*(.*?)\s*(?:#.*|//.*)?$', line)
        if match:
            return match.group(1).strip().strip('"').lower()
    return None


def _nested_blocks(resource: Resource, block_name: str) -> list[str]:
    blocks: list[str] = []
    lines = resource.body.splitlines()
    index = 1
    while index < len(lines):
        if re.match(rf'^\s*{re.escape(block_name)}\s*\{{', lines[index]):
            depth = _brace_delta(lines[index])
            collected = [lines[index]]
            index += 1
            while index < len(lines) and depth > 0:
                depth += _brace_delta(lines[index])
                collected.append(lines[index])
                index += 1
            blocks.append("\n".join(collected))
        else:
            index += 1
    return blocks


def _has_public_access_block(source: str) -> bool:
    for resource in parse_resources(source):
        if resource.kind != "aws_s3_bucket_public_access_block":
            continue
        if _attribute(resource, "block_public_acls") == "true" and _attribute(resource, "block_public_policy") == "true" and _attribute(resource, "ignore_public_acls") == "true" and _attribute(resource, "restrict_public_buckets") == "true":
            return True
    return False


def scan_source(source: str, file: str = "main.tf") -> list[Finding]:
    resources = parse_resources(source)
    findings: list[Finding] = []
    public_block = _has_public_access_block(source)

    def add(resource: Resource, rule_id: str, severity: str, title: str, description: str, remediation: str) -> None:
        findings.append(Finding(rule_id, severity, title, file, resource.start_line,
                                f"{resource.kind}.{resource.name}", description, remediation))

    for resource in resources:
        if resource.kind == "aws_s3_bucket":
            acl = _attribute(resource, "acl")
            if acl in {"public-read", "public-read-write", "authenticated-read"}:
                add(resource, "CS-AWS-001", "CRITICAL", "S3 bucket has a public ACL",
                    f"The bucket ACL is set to {acl}, which can expose stored objects.",
                    "Remove the public ACL and grant access through narrowly scoped IAM policies.")
            if not public_block:
                add(resource, "CS-AWS-002", "HIGH", "S3 public access block not found",
                    "No complete aws_s3_bucket_public_access_block was found in this file.",
                    "Add an aws_s3_bucket_public_access_block resource with all four controls enabled.")

        if resource.kind == "aws_security_group" or resource.kind == "aws_vpc_security_group_ingress_rule":
            ingress_blocks = _nested_blocks(resource, "ingress") if resource.kind == "aws_security_group" else [resource.body]
            for block in ingress_blocks:
                cidrs = re.findall(r'\bcidr_blocks\s*=\s*\[([^\]]*)\]', block)
                ipv6 = re.findall(r'\bipv6_cidr_blocks\s*=\s*\[([^\]]*)\]', block)
                open_to_world = any("0.0.0.0/0" in values or "::/0" in values for values in cidrs + ipv6)
                if not open_to_world:
                    continue
                ports = re.search(r'\b(?:from_port|to_port)\s*=\s*"?(\d+)', block)
                port = int(ports.group(1)) if ports else None
                if port is None or port in SENSITIVE_PORTS:
                    add(resource, "CS-AWS-003", "HIGH", "Sensitive ingress is open to the internet",
                        f"Ingress allows 0.0.0.0/0 or ::/0 on {f'port {port}' if port else 'a port that could not be determined'}.",
                        "Restrict ingress to required source ranges and expose only necessary ports.")
                    break

        if resource.kind == "aws_ebs_volume" and _attribute(resource, "encrypted") != "true":
            add(resource, "CS-AWS-004", "MEDIUM", "EBS volume encryption is not enabled",
                "The volume does not explicitly set encrypted = true.",
                "Set encrypted = true and use an approved KMS key where required.")

        if resource.kind == "aws_db_instance" and _attribute(resource, "storage_encrypted") != "true":
            add(resource, "CS-AWS-005", "HIGH", "RDS storage encryption is not enabled",
                "The database instance does not explicitly set storage_encrypted = true.",
                "Enable storage encryption and plan any required migration for existing data.")

        if resource.kind == "aws_cloudtrail" and _attribute(resource, "enable_log_file_validation") != "true":
            add(resource, "CS-AWS-006", "MEDIUM", "CloudTrail log file validation is disabled",
                "The trail does not explicitly enable log file integrity validation.",
                "Set enable_log_file_validation = true to validate delivered log files.")

    return sorted(findings, key=lambda item: (SEVERITIES.index(item.severity), item.file, item.line, item.rule_id))


def scan_path(path: Path, exclude_dirs: set[str] | None = None) -> list[Finding]:
    """Scan one Terraform file or recursively scan a directory."""
    excluded = exclude_dirs or {".terraform", ".git"}
    if path.is_file():
        files = [path] if path.suffix == ".tf" else []
        base = path.parent
    elif path.is_dir():
        files = [item for item in path.rglob("*.tf") if not any(part in excluded for part in item.parts)]
        base = path
    else:
        raise FileNotFoundError(f"Path does not exist: {path}")
    findings: list[Finding] = []
    for item in sorted(files):
        try:
            relative = item.relative_to(base).as_posix()
        except ValueError:
            relative = item.name
        findings.extend(scan_source(item.read_text(encoding="utf-8"), relative))
    return findings


# Security

## Credential Safety

- CloudCostGuard **never** requires credentials to be embedded in source code
- Uses boto3's standard credential chain: AWS CLI profiles, environment variables, IAM instance roles, ECS/EKS IRSA
- The CLI reads credentials from the environment at runtime only
- No credentials are logged, even in debug mode
- AWS secret keys and session tokens are never printed or exposed

## Read-Only Architecture

- The default `cloudcostguard scan` command is **completely read-only**
- It only uses describe/list APIs - no create, update, or delete operations
- No instances are stopped, no volumes are deleted, no Elastic IPs are released
- No security groups are modified, no IAM changes are made
- A future architecture could support remediation, but v1 is read-only by design

## Vulnerability Reporting

If you discover a security issue, please report it responsibly:

1. **Do not** disclose vulnerabilities in public issues or Pull Requests
2. Report via the GitHub Security Advisory or email the maintainers
3. The maintainers will verify and address the issue
4. Security fixes will be released in a new version

## No Secrets in Issues/PRs

- Never include AWS credentials, keys, or tokens in issue descriptions
- Never include real account IDs or resource IDs that could be sensitive
- Redact any accidentally committed credentials immediately

## Responsible Disclosure

- Give maintainers reasonable time to address security issues
- coordinate disclosure through official channels
- Follow [GitHub's security bug bounty program](https://github.com/blog/2996-bug-bounty-program)

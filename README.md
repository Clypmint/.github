# org-profile

Repository maintenance and community files. See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Read-only portfolio audit

With Node.js and an authenticated GitHub CLI, run:

```sh
node scripts/audit-repositories.mjs Clypmint > /secure/local/repository-audit.json
```

The report inventories your owned repositories and the named organization, then summarizes native security settings, branch rules, workflow-token permissions, and open alert counts. It does not change GitHub settings or include credential values. Private repository names and alert counts are internal information: keep the output private. Unavailable checks are reported as unavailable, never as zero findings. Archived repositories are read only; fork alerts can include inherited upstream debt.

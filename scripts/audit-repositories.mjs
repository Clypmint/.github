#!/usr/bin/env node
// Read-only GitHub inventory. Never serialize raw secret-scanning responses.
import { execFileSync } from 'node:child_process';

function api(path, pages = false) {
  try {
    const value = JSON.parse(execFileSync('gh', ['api', path, ...(pages ? ['--paginate', '--slurp'] : [])], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
    }));
    return { ok: true, value: pages ? value.flat() : value };
  } catch (error) {
    // Only GitHub's structured error message is retained, never stderr or response bodies.
    let message = 'Unavailable with the current account or repository plan';
    try { message = JSON.parse(String(error.stdout)).message ?? message; } catch {}
    return { ok: false, message };
  }
}

const org = process.argv[2] || 'Clypmint';
if (!/^[a-zA-Z0-9-]+$/.test(org)) throw new Error('Provide a GitHub organization login.');
const owned = api('user/repos?affiliation=owner&per_page=100', true);
const organization = api(`orgs/${org}/repos?per_page=100`, true);
if (!owned.ok || !organization.ok) throw new Error('Unable to inventory repositories; verify gh authentication and organization access.');

const repositories = [];
for (const repo of [...owned.value, ...organization.value].sort((a, b) => a.full_name.localeCompare(b.full_name))) {
  const base = `repos/${repo.full_name}`;
  const metadata = api(base);
  const security = metadata.ok ? metadata.value.security_and_analysis ?? {} : {};
  const alerts = api(`${base}/dependabot/alerts?state=open&per_page=100`, true);
  const secrets = repo.private ? null : api(`${base}/secret-scanning/alerts?state=open&per_page=100`, true);
  const rules = api(`${base}/rulesets`);
  const permissions = api(`${base}/actions/permissions/workflow`);
  const report = {
    repository: repo.full_name, url: repo.html_url, visibility: repo.visibility,
    archived: repo.archived, fork: repo.fork, defaultBranch: repo.default_branch,
    securityFeatures: Object.fromEntries(Object.entries(security).map(([name, value]) => [name, value.status])),
    activeRulesets: rules.ok ? rules.value.filter(r => r.enforcement === 'active').map(r => ({ name: r.name, target: r.target })) : null,
    rulesetAccess: rules.ok ? 'available' : rules.message,
    workflowToken: permissions.ok ? permissions.value.default_workflow_permissions : null,
    workflowCanApprovePRs: permissions.ok ? permissions.value.can_approve_pull_request_reviews : null,
    dependencyAlerts: alerts.ok ? { total: alerts.value.length, bySeverity: {} } : { unavailable: alerts.message },
    secretAlerts: secrets === null ? { unavailable: 'Native private secret scanning requires separate entitlement; inspect repository CI.' } : secrets.ok ? { total: secrets.value.length } : { unavailable: secrets.message },
  };
  if (alerts.ok) for (const alert of alerts.value) {
    const severity = alert.security_advisory?.severity ?? 'unknown';
    report.dependencyAlerts.bySeverity[severity] = (report.dependencyAlerts.bySeverity[severity] ?? 0) + 1;
  }
  repositories.push(report);
}
process.stdout.write(`${JSON.stringify({ generatedAt: new Date().toISOString(), repositories }, null, 2)}\n`);

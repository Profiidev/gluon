import * as core from '@actions/core';

const LEVELS = new Set(['read', 'write', 'admin']);

interface TokenResponse {
  token: string;
  expires_at: string;
}

const list = (input: string) =>
  input
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);

export const parsePermissions = (input: string): Record<string, string> => {
  const trimmed = input.trim();
  if (!trimmed) {
    return {};
  }
  const entries: [string, string][] = trimmed.startsWith('{')
    ? Object.entries(JSON.parse(trimmed) as Record<string, string>)
    : list(trimmed).map((pair) => {
        const [name, level] = pair.split(/[:=]/).map((s) => s.trim());
        return [name ?? '', level ?? ''];
      });
  for (const [name, level] of entries) {
    if (!name || !LEVELS.has(level)) {
      throw new Error(
        `Invalid permission "${name}:${level}", expected name:read|write|admin`
      );
    }
  }
  return Object.fromEntries(entries);
};

export const parseRepositories = (input: string) => {
  const repositories: string[] = [],
    repositoryIds: number[] = [];
  for (const repo of list(input)) {
    if (/^\d+$/.test(repo)) {
      repositoryIds.push(Number(repo));
    } else if (/^[^/\s]+\/[^/\s]+$/.test(repo)) {
      repositories.push(repo);
    } else {
      throw new Error(
        `Invalid repository "${repo}", expected owner/name or an ID`
      );
    }
  }
  return { repositories, repositoryIds };
};

const errorMessage = async (res: Response) => {
  try {
    const body = (await res.json()) as {
      error?: string;
      error_description?: string;
    };
    return `${body.error ?? 'error'}: ${body.error_description ?? ''}`;
  } catch {
    return res.statusText;
  }
};

export const main = async () => {
  try {
    // Marks the post step; state is only visible to post when set in main.
    core.saveState('isPost', 'true');

    const url = core.getInput('url', { required: true }).replace(/\/+$/, ''),
      audience = core.getInput('audience') || 'github-token-broker',
      profile = core.getInput('profile'),
      permissions = parsePermissions(core.getInput('permissions')),
      { repositories, repositoryIds } = parseRepositories(
        core.getInput('repositories')
      ),
      body: Record<string, unknown> = {};
    if (repositories.length > 0) {
      body.repositories = repositories;
    }
    if (repositoryIds.length > 0) {
      body.repository_ids = repositoryIds;
    }
    if (Object.keys(permissions).length > 0) {
      body.permissions = permissions;
    }
    if (profile) {
      body.profile = profile;
    }

    const oidc = await core.getIDToken(audience),
      res = await fetch(`${url}/v1/token`, {
        body: JSON.stringify(body),
        headers: {
          Authorization: `Bearer ${oidc}`,
          'Content-Type': 'application/json'
        },
        method: 'POST'
      });
    if (!res.ok) {
      throw new Error(
        `Broker refused the request (${res.status}): ${await errorMessage(res)}`
      );
    }
    const data = (await res.json()) as TokenResponse;
    core.setSecret(data.token);
    core.setOutput('token', data.token);
    core.setOutput('expires_at', data.expires_at);
    core.saveState('token', data.token);
    core.info(`Received token, expires at ${data.expires_at}`);
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
};

export const post = async () => {
  const token = core.getState('token');
  if (!token) {
    core.info('No token to revoke');
    return;
  }
  if (core.getBooleanInput('skip-revoke')) {
    core.info('Skipping token revocation');
    return;
  }
  try {
    const api = (
        core.getInput('github-api-url') || 'https://api.github.com'
      ).replace(/\/+$/, ''),
      res = await fetch(`${api}/installation/token`, {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'X-GitHub-Api-Version': '2022-11-28'
        },
        method: 'DELETE'
      });
    // 401: already expired or revoked.
    if (res.ok || res.status === 401) {
      core.info('Token revoked');
    } else {
      core.warning(`Token revocation failed (${res.status})`);
    }
  } catch (error) {
    // Never fail the job in cleanup.
    core.warning(
      `Token revocation failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
};

export const run = () => (core.getState('isPost') === 'true' ? post() : main());

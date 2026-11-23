import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@actions/core');

const core = await import('@actions/core'),
  { main, post, run, parsePermissions, parseRepositories } =
    await import('../run'),
  fetchMock = vi.fn(),
  setInputs = (inputs: Record<string, string>) => {
    vi.mocked(core.getInput).mockImplementation((name) => inputs[name] ?? '');
    vi.mocked(core.getBooleanInput).mockImplementation(
      (name) => inputs[name] === 'true'
    );
  },
  setState = (state: Record<string, string>) => {
    vi.mocked(core.getState).mockImplementation((name) => state[name] ?? '');
  },
  json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status });

beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal('fetch', fetchMock);
  setInputs({ url: 'https://broker.example.com/' });
  setState({});
  vi.mocked(core.getIDToken).mockResolvedValue('oidc-jwt');
});

describe('input parsing', () => {
  it('parses permission pairs and JSON', () => {
    expect(
      parsePermissions('contents:write, pull_requests=read\nissues: read')
    ).toEqual({
      contents: 'write',
      issues: 'read',
      pull_requests: 'read'
    });
    expect(parsePermissions('{"contents":"admin"}')).toEqual({
      contents: 'admin'
    });
    expect(parsePermissions('  ')).toEqual({});
    expect(() => parsePermissions('contents:root')).toThrow(
      /Invalid permission/
    );
    expect(() => parsePermissions('contents')).toThrow(/Invalid permission/);
  });

  it('splits repositories into names and ids', () => {
    expect(parseRepositories('Profiidev/foo, 123\nProfiidev/bar')).toEqual({
      repositories: ['Profiidev/foo', 'Profiidev/bar'],
      repositoryIds: [123]
    });
    expect(() => parseRepositories('nope')).toThrow(/Invalid repository/);
  });
});

describe('main', () => {
  it('requests a token and masks it', async () => {
    setInputs({
      audience: 'aud',
      permissions: 'contents:write',
      profile: 'release',
      repositories: 'Profiidev/foo,42',
      url: 'https://broker.example.com/'
    });
    fetchMock.mockResolvedValue(
      json(200, { expires_at: '2099-01-01T00:00:00Z', token: 'ghs_x' })
    );

    await main();

    expect(core.getIDToken).toHaveBeenCalledWith('aud');
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://broker.example.com/v1/token');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>).Authorization).toBe(
      'Bearer oidc-jwt'
    );
    expect(JSON.parse(init.body as string)).toEqual({
      permissions: { contents: 'write' },
      profile: 'release',
      repositories: ['Profiidev/foo'],
      repository_ids: [42]
    });
    expect(core.setSecret).toHaveBeenCalledWith('ghs_x');
    expect(core.setOutput).toHaveBeenCalledWith('token', 'ghs_x');
    expect(core.setOutput).toHaveBeenCalledWith(
      'expires_at',
      '2099-01-01T00:00:00Z'
    );
    expect(core.saveState).toHaveBeenCalledWith('token', 'ghs_x');
    expect(core.saveState).toHaveBeenCalledWith('isPost', 'true');
    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it('sends an empty body by default', async () => {
    fetchMock.mockResolvedValue(json(200, { expires_at: 'x', token: 't' }));
    await main();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.body).toBe('{}');
    expect(core.getIDToken).toHaveBeenCalledWith('github-token-broker');
  });

  it('fails with the broker error', async () => {
    fetchMock.mockResolvedValue(
      json(403, {
        error: 'access_denied',
        error_description: 'The request is not permitted.'
      })
    );
    await main();
    expect(core.setFailed).toHaveBeenCalledWith(
      'Broker refused the request (403): access_denied: The request is not permitted.'
    );
    expect(core.setOutput).not.toHaveBeenCalled();
  });

  it('fails on bad input without calling the broker', async () => {
    setInputs({ permissions: 'contents:root', url: 'https://b' });
    await main();
    expect(core.setFailed).toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('post', () => {
  it('revokes the token', async () => {
    setState({ isPost: 'true', token: 'ghs_x' });
    setInputs({ 'github-api-url': 'https://ghe.example.com/api/v3/' });
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));

    await run();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://ghe.example.com/api/v3/installation/token');
    expect(init.method).toBe('DELETE');
    expect((init.headers as Record<string, string>).Authorization).toBe(
      'Bearer ghs_x'
    );
    expect(core.warning).not.toHaveBeenCalled();
  });

  it('honours skip-revoke', async () => {
    setState({ token: 'ghs_x' });
    setInputs({ 'skip-revoke': 'true' });
    await post();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does nothing without a token', async () => {
    await post();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('only warns when revocation fails', async () => {
    setState({ token: 'ghs_x' });
    fetchMock.mockRejectedValue(new Error('offline'));
    await post();
    expect(core.warning).toHaveBeenCalledWith(
      'Token revocation failed: offline'
    );
    expect(core.setFailed).not.toHaveBeenCalled();
  });
});

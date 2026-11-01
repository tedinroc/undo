// Where a page gets its authenticator. The path is built at run time so site/build.mjs's walk does not
// reach the software authenticator from a normal page: it ships only when a config sets softPasskey.

/**
 * @param browser navigator.credentials, passed in by the page
 * @param soft { secret, origin } when the config allows a software key. The page holds the secret in memory
 */
export async function credentialsFor(config, { browser = globalThis.navigator?.credentials, soft = null, softPath = ['', 'site', 'lib', 'soft-authenticator.mjs'].join('/') } = {}) {
  if (!config.softPasskey) {
    if (!browser) throw new Error('this browser has no passkeys');
    return browser;
  }
  if (!soft) throw new Error('a software passkey needs a key');
  const { softCredentials } = await import(softPath);
  return softCredentials({ ...soft, rpId: config.rpId });
}

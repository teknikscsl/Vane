const BLOCKED_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata.goog',
]);

const BLOCKED_IPS = new Set([
  '169.254.169.254',
  'fd00:ec2::254',
]);

export function validateProviderBaseURL(url: string): string {
  const trimmed = url.trim();

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('Invalid base URL: not a valid URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `Invalid base URL: scheme "${parsed.protocol}" is not allowed. Use http or https.`,
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error('Invalid base URL: embedded credentials are not allowed');
  }

  const hostname = parsed.hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new Error('Invalid base URL: this host is not allowed');
  }

  if (BLOCKED_IPS.has(hostname)) {
    throw new Error('Invalid base URL: this IP address is not allowed');
  }

  const bareIPv6 = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;

  if (BLOCKED_IPS.has(bareIPv6)) {
    throw new Error('Invalid base URL: this IP address is not allowed');
  }

  return trimmed;
}

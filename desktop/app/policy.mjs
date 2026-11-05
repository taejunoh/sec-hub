// Only a server URL returned by the main-process controller establishes trust.
function ownedOrigin(value) {
  if (typeof value !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]*\/$/.test(value)) return null;
  try {
    const url = new URL(value);
    return Number(url.port) > 0 && url.origin + '/' === value ? url.origin : null;
  } catch { return null; }
}

export function isOwnedUrl(value, ownedUrl) {
  const origin = ownedOrigin(ownedUrl);
  if (!origin || typeof value !== 'string' || !value.startsWith(`${origin}/`)) return false;
  try {
    const url = new URL(value);
    return url.origin === origin && !url.username && !url.password;
  } catch { return false; }
}

export function browserUrl(value, ownedUrl) {
  return isOwnedUrl(value, ownedUrl) ? value : null;
}

export function isTrustedSender(event, contents, session, activeUrl) {
  if (!contents || contents.isDestroyed() || event.sender !== contents || contents.session !== session) return false;
  const frame = event.senderFrame;
  return Boolean(frame && frame === contents.mainFrame && frame.url === activeUrl && isOwnedUrl(frame.url, activeUrl));
}

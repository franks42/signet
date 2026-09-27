# End-to-end protection through TLS-terminating proxies

Status: **design note, 2026-09-27.** Nothing is built yet. It records a
discussion: the problem, what exists, what signet already has, and what a
first slice could be.

## The problem

Many web applications sit behind an edge proxy (Cloudflare, AWS
CloudFront, Azure Front Door, Google Cloud CDN, Akamai, …) that
terminates TLS. The browser's TLS channel ends at the proxy. If the
operator is careful, a second TLS channel carries the request on to the
application server. Either way **the proxy sees every request and
response in plaintext**. For a large share of the web that is one company
in one place, under whatever jurisdiction the edge node sits in.

The convenience is real (DDoS protection, caching, WAF, global routing,
certificate management), and the trust is usually settled by contract.
But it is trust in a third party that the user never chose, and it is
not a technical guarantee.

**Is it a real concern?** Yes:
- **Cloudbleed (February 2017)** [source]: a Cloudflare HTML-parser bug
  leaked uninitialised memory into responses: other customers' plaintext
  traffic, including cookies, tokens and POST bodies, some of it cached
  by search engines.
- Plaintext at the edge can be **compelled** (lawful access) and is
  **processed and stored** in normal operation (logs, WAF analytics,
  sampling).
- **Keyless SSL** [source] keeps the site's TLS private key off the
  proxy, but the proxy still decrypts the traffic: it protects the key,
  not the data.

For high-value data (credentials, keys, health, financial data, secrets:
exactly what signet exists for), end-to-end protection past the proxy is
justified.

## Who we defend against

The value of any design depends on which proxy we assume:

| Proxy behaviour | Example | Can application-layer E2E help? |
|---|---|---|
| **Honest but curious**: logs, samples, analyses | WAF analytics, debug logging | Yes: it only sees ciphertext |
| **Breached or buggy** | Cloudbleed; a compromised edge node | Yes: leaked memory holds ciphertext |
| **Compelled**: hands over stored or live data | lawful access at the edge | Yes for content; metadata still visible |
| **Actively malicious**: rewrites what it serves | injected JavaScript | **Only if code and keys are anchored outside the proxy** (below) |

The honest claim: application-layer E2E removes the proxy's plaintext by
default and protects fully against the first three. Against the fourth
it forces the proxy to tamper with code, which is detectable and a
scandal, unless code integrity is anchored elsewhere.

## The two hard problems (not the crypto)

### 1. The code comes through the proxy

The JavaScript that does the key exchange is served by the same proxy. A
malicious proxy can change it to exfiltrate keys or plaintext.
Subresource Integrity does not help: the HTML carrying the hashes comes
through the proxy too. Ways to anchor code outside the proxy:
- **Installed code:** a native app, a browser extension, or a
  desktop/mobile wrapper, updated through a signed channel.
- **Isolated Web Apps** (Chrome) [source]: web apps shipped as
  developer-signed bundles, installed rather than fetched on each load.
- **Code transparency:** publish the hashes of every served bundle; an
  independent checker compares (Meta's Code Verify for WhatsApp Web
  [source]).

Without one of these, the design defends against the first three rows
of the table, not the fourth.

#### Where the code comes from: public CDNs, SRI, signatures (added 2026-09-27)

**JavaScript from a public CDN is not signed by default.** TLS proves the
browser reached the CDN, not that the file is what the author published;
the CDN can serve anything at that URL (a bug, a compromise, a change of
owner). This has happened: **polyfill.io (2024)** [source], whose domain
was sold and then served malware to more than 100,000 sites, and
**British Airways / Magecart (2018)** [source], card skimming injected
through a third-party script.

**Subresource Integrity** pins the exact hash in the page
(`<script src=… integrity="sha384-…">`): the browser refuses anything
else, so the library CDN can only deny service. **That is the difference
from the site's own proxy:** a public CDN serves a separate resource
whose hash the page can pin; the proxy serves **the page itself**, the
HTML that carries the hashes, and nothing earlier in the chain can pin
that. The trust chain is:
1. TLS authenticates whoever answers for the domain: the proxy;
2. the HTML, served by that proxy, pins third-party scripts with SRI;
3. those scripts are safe from their CDN, but only as safe as the HTML.

**Signatures exist but browsers mostly do not check them.** npm registry
signatures and Sigstore provenance (2023) [source] are verified by `npm`
at install, not by a browser loading from a CDN. **Signed HTTP Exchanges
(SXG)** [source] let an origin sign responses that an intermediary serves
and the browser verifies: the closest browser mechanism, but
Chromium-only, with signatures valid for at most 7 days and little
adoption. **Isolated Web Apps** sign the whole app.

**Our own projects:** canonical-edn's README loads its Scittle bundle
from jsDelivr at a pinned tag without an integrity hash. An `integrity`
attribute would not help as it stands: a `<script
type="application/x-scittle">` is fetched by Scittle, not by the
browser's script loader, which ignores the attribute [inference]. Scittle
would have to check hashes itself, or the README could document another
way to verify the bundle. The same likely applies to libsodium.js as
loaded in nacljc's browser tests. A small follow-up: check whether
Scittle supports integrity checks.

### 2. The server's key must be authentic

For the browser to encrypt to the application server, it needs the
server's public key. Delivered through the proxy, the proxy can swap in
its own. The key has to be anchored somewhere the proxy does not control:
- in the signed code bundle (Isolated Web Apps, installed apps);
- in DNS with DNSSEC;
- in a key-transparency log;
- pinned on first use (TOFU), with a clear warning when it changes.

## What the proxy keeps, loses, and still sees

- **Keeps:** routing (host, path, method), caching of public assets, DDoS
  protection, rate limiting by IP and endpoint, TLS certificate
  management.
- **Loses:** WAF inspection and bot detection on encrypted bodies. This
  is the real operational cost; abuse protection moves to the application
  or to what remains visible (rates, sizes, paths).
- **Still sees:** metadata: endpoints, sizes, timing, client IPs,
  unencrypted headers.
- **Sessions are the trap.** Cookies and bearer tokens in headers stay
  visible, so a proxy could replay them. Authorisation has to be bound
  to the protected channel: requests signed with a client key (as in
  DPoP, RFC 9449 [source], or signet's `sign-edn`), or the session token
  itself carried inside the encrypted payload.

### Cookies through the proxy (added 2026-09-27)

How it works: the application server sends `Set-Cookie` in its response;
the proxy forwards the header; the browser stores the cookie for the
domain in the address bar. With a CDN, DNS for that domain points at the
proxy, so to the browser the proxy *is* the site. Cookies are scoped by
domain and path, not by server or IP. On every later request the browser
sends `Cookie:` to the proxy, which forwards it.

So the proxy:
- **reads every cookie** in both directions, in plaintext (session ids,
  auth tokens, CSRF tokens);
- **can strip, rewrite or add** cookies (CDNs set their own, e.g.
  Cloudflare's `__cf_bm` and `cf_clearance` [source]);
- **can plant a cookie** in the site's name (session fixation);
- **can replay a session cookie** from anywhere, indistinguishable from
  the user.

`Secure`, `HttpOnly` and `SameSite` do not help: the browser enforces them
against page scripts, other sites and plain HTTP, and the proxy sits
inside the TLS channel the browser trusts.

Ways out, so that a cookie never carries authority on its own:
- **Bind the session to a client key.** The browser keeps a
  non-extractable key (WebCrypto, in IndexedDB) and signs each request;
  the cookie only *names* the session. The proxy sees the cookie but
  cannot sign. This is DPoP's idea, and what signet's `sign-edn` does.
- **Carry the session token inside the encrypted payload,** so no bearer
  credential travels in a visible header.
- **Device Bound Session Credentials** (DBSC, Chrome) [source]:
  short-lived cookies, renewed by signing a challenge with a
  hardware-backed key. Aimed at cookie-stealing malware; against a proxy
  it only shortens the window, since the proxy sees each short-lived
  cookie while it is valid.
- **Encrypting the cookie value alone does not help:** the proxy replays
  the encrypted blob.

For the first slice: keep a cookie where routing or load balancers need
one, but grant authority only through a signature over the request, made
with a key the proxy never sees.

### Signed URLs and redirects (added 2026-09-27)

**Signing a URL** is common (S3 presigned URLs, CloudFront signed URLs,
HMAC-signed image URLs), and **HTTP Message Signatures (RFC 9421)**
[source] standardise signing whole requests: chosen components (method,
target URI, selected headers), Ed25519 among the algorithms. signet's
`sign-edn` could sign the same content as EDN (method, path, query,
expiry, nonce).

Against the proxy, a signed URL gives **integrity** (the path and query
cannot be changed, nor a URL for another resource forged), **not
confidentiality** (the proxy still reads it; sensitive data does not
belong in URLs, which end up in logs and `Referer`), and replay stays
possible unless the signature covers a short expiry and, for sensitive
actions, a one-time nonce. Who signs matters:
- **the browser signs its requests** (its client key): the server knows
  the proxy did not alter what the user's code sent;
- **the server signs URLs it hands out** (capability or magic links):
  the server knows a returning URL is one it issued, unaltered.

**A signed redirect is not checked by the browser.** A redirect is a
`Location:` header; the proxy can replace it with any URL, and the browser
follows it. The signature helps only where something checks it:
1. **the destination server** verifies the parameters it receives, as
   signed OAuth/OIDC request objects (JAR, RFC 9101) and signed SAML
   requests do. That protects the destination from tampered parameters,
   not the user from being sent elsewhere;
2. **the client code** verifies a signed "go to X" response against a
   pinned server key before navigating. That protects the user, but only
   as far as the client code is itself authentic (problem 1).

An actively malicious proxy controls the whole domain as the browser sees
it: it does not need to tamper with redirects, it can serve any page.
Signed URLs and redirects help against passive, breached and buggy
proxies; against a malicious one only code anchored outside the proxy
helps.

## Existing solutions

The idea is established; there is no single general toolkit for it.

1. **Client-side encryption for payments** (Braintree, Adyen, Stripe
   hosted fields) [source]: card data is encrypted in the browser to the
   payment processor's key, so neither the merchant nor its CDN sees it.
   Field-level E2E, deployed at scale.
2. **Zero-knowledge web apps** (1Password, Bitwarden, Proton) [source]:
   data is encrypted in the browser; servers and CDNs see ciphertext.
   They also face problem 1 and address it partly with installed apps
   and extensions.
3. **Oblivious HTTP (RFC 9458)** on **HPKE (RFC 9180)** [source]: a
   request is encapsulated to a gateway's public key and passes a relay
   that cannot read it. Standardised and deployed (Apple Private Relay,
   Chrome; Cloudflare runs relays). The closest standard shape for
   "encrypted payload, transparent transport", though designed to hide
   who asks from the gateway rather than content from a CDN.
4. **DPoP (RFC 9449):** proof of possession for OAuth tokens: a stolen or
   observed token is useless without the client's key.
5. **TLS passthrough** (layer-4 proxying, e.g. Cloudflare Spectrum): the
   proxy does not terminate TLS at all, at the cost of caching, WAF and
   content routing.
6. **Messaging protocols** (Signal, MLS): E2E between users, not between
   a browser and its application server, but the same building blocks.

## What we have, and what is missing

**Have:**
- libsodium on the server (nacljc) and in the browser (libsodium.js,
  already tested against nacljc's vectors in Node and in headless
  Chrome). WebCrypto now also has X25519 and Ed25519 [source].
- signet: signed EDN envelopes (`sign-edn`, request binding), box
  (per-message, sender-authenticated encryption), Noise KK sessions,
  handles and the vault.

**Missing:**
- **signet in ClojureScript.** Every `:cljs` branch throws today. This
  is the largest piece. The vault's `:webcrypto` provider (docs/07) fits
  here: non-extractable browser keys.
- **A handshake that fits browsers.** KK assumes both sides have
  long-term keys. A browser usually knows only the server's key: Noise
  **NK** (the client stays anonymous), **XK** (the client proves a key
  later), or **IK** (0-RTT with a client key). Or no session at all (next
  point).
- **Per-request or session?**

  | | Per request (box / HPKE) | Session (Noise) |
  |---|---|---|
  | Behind load balancers | stateless: any server can answer | needs session affinity or shared state |
  | Forward secrecy | a later server-key compromise exposes past requests | yes (ephemeral-ephemeral DH) |
  | Round trips | none extra | one handshake |
  | Fit with signet | box already works this way | KK exists; NK/XK/IK needed |

  A first slice is simpler per request; sessions can follow where
  forward secrecy matters.
- **The HTTP binding:** Ring middleware on the server, a `fetch` wrapper
  in the browser, and a message format. Adopting OHTTP's framing (or
  HPKE's suite identifiers) would make it reviewable and interoperable,
  rather than inventing a format.
- **Key anchoring and code integrity** (above): documentation and
  deployment guidance more than code, but they decide what the whole thing
  is worth.

## A possible first slice

1. **Scope:** protect selected request and response bodies (a JSON or EDN
   payload), with paths, methods and public assets left transparent for
   the proxy.
2. **Per request:** the browser encrypts to the server's published X25519
   key with a fresh ephemeral key (HPKE base mode, or signet box with an
   ephemeral sender). The response is encrypted under a key derived from
   the same exchange, as OHTTP does.
3. **Authorisation inside:** the client signs the request (Ed25519) and
   the signature travels inside the encrypted payload, so tokens in
   headers are not needed or not sufficient.
4. **Server side:** Ring middleware that decrypts, verifies and hands the
   application an ordinary request, in Clojure on the JVM or bb.
5. **Browser side:** first with libsodium.js from plain JavaScript or
   Scittle, before a full ClojureScript signet.
6. **Key anchoring:** start with TOFU plus an explicit pin in the served
   configuration, with documentation of what that does and does not
   protect; offer DNSSEC or a signed bundle as the stronger option.

## Open questions

1. **Adopt HPKE and OHTTP framing, or signet's own box format?** Standards
   bring review and interoperability; signet's format is EDN-native and
   already has directional keys and key commitment.
2. **Which Noise pattern,** if sessions come later: NK, XK or IK?
3. **Key anchoring default:** TOFU with a pin, DNSSEC, or signed bundles
   only?
4. **Where it lives:** part of signet, or a companion library (e.g.
   "signet-http") on top of signet, like stroopwafel?
5. **Abuse protection** without body inspection: what the proxy's WAF did
   that the application must now do.
6. **Metadata:** padding sizes, or accepting that the proxy sees them.

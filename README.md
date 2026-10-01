# VulnCue\TOTP

A tiny, dependency-free PHP implementation of TOTP ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)) and HOTP ([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)) — the algorithm behind Google Authenticator, Authy, 1Password, Microsoft Authenticator and every other standard "6-digit code" two-factor app.

- **Zero dependencies.** No Composer packages required, no PHP extensions beyond what ships in a default build (`hash`, `random_bytes`).
- **Verified against the official RFC test vectors.** All 10 HOTP vectors from RFC 4226 Appendix D and all 5 TOTP vectors from RFC 6238 Appendix B pass — see [`tests/rfc-vectors-test.php`](tests/rfc-vectors-test.php), runnable on its own.
- **Framework-agnostic.** One class, no base class to extend, no service container to wire up.

Extracted from the free, built-in two-factor authentication feature of the [VulnCue WordPress security plugin](https://wordpress.org/plugins/vulncue/) ([vulncue.com](https://vulncue.com)), where it runs the login-time TOTP/backup-code verification for real production sites.

## Install

Copy `src/TOTP.php` into your project, or require it directly — there is no Composer package yet, intentionally, to keep this a single file you can audit in under a minute.

```php
require 'src/TOTP.php';

use VulnCue\TOTP;
```

## Usage

### 1. Generate a secret and show a QR code

```php
$secret = TOTP::generateSecret(); // Base32, e.g. "JBSWY3DPEHPK3PXP..."

$uri = TOTP::provisioningUri($secret, 'jane@example.com', 'My App');
// otpauth://totp/My%20App:jane%40example.com?secret=...&issuer=My+App&algorithm=SHA1&digits=6&period=30
```

Feed `$uri` to any client-side QR library (e.g. [qrcodejs](https://github.com/davidshimjs/qrcodejs)) to render a scannable code — no server round-trip needed, and no external API call that would leak the secret.

### 2. Verify a code at login

```php
if (TOTP::verify($storedSecret, $_POST['code'])) {
    // correct — allow for up to ±30s of clock drift either way (window=1, the default)
} else {
    // incorrect
}
```

`verify()` uses `hash_equals()` internally to avoid timing attacks, and never throws on malformed input — it just returns `false`.

### 3. Lower-level HOTP/TOTP if you need them directly

```php
TOTP::hotp($secret, $counter);      // RFC 4226, a specific counter value
TOTP::totp($secret);                // RFC 6238, current 30s time step
TOTP::totp($secret, time(), 30, 8); // 8-digit code, if your use case needs it (RFC 6238's own test vectors use 8 digits)
```

## Why this exists

Most PHP TOTP libraries either pull in a Composer dependency tree for something that's genuinely ~130 lines of code, or get the HOTP truncation step subtly wrong. We needed something we could read end-to-end in a code review and verify byte-for-byte against the RFCs before shipping it in front of real logins — so we wrote this, tested it against every published RFC vector, and figured other people building their own 2FA might want the same thing without the dependency.

## What this is *not*

This is the cryptographic primitive only — it does not store secrets, does not rate-limit login attempts, does not generate backup codes, and does not know anything about sessions or cookies. All of that is application-specific and belongs in your own code (see how [VulnCue's own 2FA](https://vulncue.com) wires this into a full login flow, including encryption at rest, backup codes and a kill switch, if you want a reference).

## License

MIT — see [LICENSE](LICENSE).

<?php

declare(strict_types=1);

/**
 * Verifies VulnCue\TOTP against the official published test vectors:
 *  - RFC 4226 Appendix D (HOTP, counters 0-9)
 *  - RFC 6238 Appendix B (TOTP, SHA1 case, 8-digit codes)
 *
 * Run: php tests/rfc-vectors-test.php
 */

require __DIR__ . '/../src/TOTP.php';

use VulnCue\TOTP;

$failures = 0;
$total = 0;

function check(string $label, string $expected, string $actual, int &$total, int &$failures): void
{
    $total++;
    $ok = hash_equals($expected, $actual);
    if (!$ok) {
        $failures++;
    }
    echo ($ok ? 'PASS' : 'FAIL') . "  {$label}  expected={$expected} actual={$actual}\n";
}

// RFC 4226 Appendix D — HOTP, secret = ASCII "12345678901234567890" (20 bytes), 6 digits.
$secret20 = TOTP::base32Encode('12345678901234567890');
$rfc4226 = [
    0 => '755224', 1 => '287082', 2 => '359152', 3 => '969429', 4 => '338314',
    5 => '254676', 6 => '287922', 7 => '162583', 8 => '399871', 9 => '520489',
];
foreach ($rfc4226 as $counter => $expected) {
    check("RFC4226 HOTP counter={$counter}", $expected, TOTP::hotp($secret20, $counter, 6), $total, $failures);
}

// RFC 6238 Appendix B — TOTP, SHA1 case, same 20-byte secret, 8-digit codes, 30s step.
$rfc6238 = [
    59 => '94287082',
    1111111109 => '07081804',
    1111111111 => '14050471',
    1234567890 => '89005924',
    2000000000 => '69279037',
];
foreach ($rfc6238 as $ts => $expected) {
    check("RFC6238 TOTP t={$ts}", $expected, TOTP::totp($secret20, $ts, 30, 8), $total, $failures);
}

// Base32 round-trip (including null/0xFF bytes) + verify() window tolerance,
// as a basic sanity check beyond the RFC vectors.
$rawBytes = "some raw bytes \x00\xFF";
$roundTrip = TOTP::base32Decode(TOTP::base32Encode($rawBytes));
check('base32 round-trip (binary-safe)', bin2hex($rawBytes), bin2hex($roundTrip), $total, $failures);

$freshSecret = TOTP::generateSecret();
$codeNow = TOTP::totp($freshSecret);
check('verify() accepts the current code', 'true', TOTP::verify($freshSecret, $codeNow) ? 'true' : 'false', $total, $failures);
check('verify() rejects garbage', 'false', TOTP::verify($freshSecret, '000000', 0, 1) ? 'true' : 'false', $total, $failures);

echo "\n{$total} checks, " . ($total - $failures) . " passed, {$failures} failed.\n";
exit($failures > 0 ? 1 : 0);

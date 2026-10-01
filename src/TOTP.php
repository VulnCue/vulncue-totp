<?php

declare(strict_types=1);

namespace VulnCue;

/**
 * Pure-PHP TOTP (RFC 6238) / HOTP (RFC 4226) implementation.
 *
 * Zero dependencies, no framework assumptions. Verified against the official
 * test vectors published in RFC 4226 Appendix D and RFC 6238 Appendix B — see
 * tests/rfc-vectors-test.php.
 *
 * Originally written for VulnCue's free two-factor authentication feature for
 * WordPress (https://wordpress.org/plugins/vulncue/) and extracted here as a
 * standalone library. https://vulncue.com
 *
 * @license MIT
 */
final class TOTP
{
    public const DEFAULT_PERIOD = 30;
    public const DEFAULT_DIGITS = 6;
    public const SECRET_BYTES = 20; // 160 bits — what Google Authenticator, Authy, etc. use.

    /** RFC 4648 Base32 alphabet (no padding in the secret shown to the user). */
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Cryptographically secure random secret, already Base32-encoded (ready to show/store). */
    public static function generateSecret(int $bytes = self::SECRET_BYTES): string
    {
        return self::base32Encode(random_bytes(max(10, $bytes)));
    }

    public static function base32Encode(string $binary): string
    {
        if ($binary === '') {
            return '';
        }
        $bits = '';
        for ($i = 0, $len = strlen($binary); $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($binary[$i])), 8, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= self::BASE32_ALPHABET[bindec($chunk)];
        }
        return $output;
    }

    /** Accepts a secret with spaces/lowercase letters (as a user might paste it by hand). */
    public static function base32Decode(string $base32): string
    {
        $base32 = strtoupper((string) preg_replace('/[^A-Za-z2-7]/', '', $base32));
        if ($base32 === '') {
            return '';
        }
        $bits = '';
        foreach (str_split($base32) as $char) {
            $pos = strpos(self::BASE32_ALPHABET, $char);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $binary = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) < 8) {
                break; // leftover padding bits, not a full byte
            }
            $binary .= chr((int) bindec($byte));
        }
        return $binary;
    }

    /** RFC 4226 HOTP — dynamic truncation over HMAC-SHA1(key, 8-byte big-endian counter). */
    public static function hotp(string $secretBase32, int $counter, int $digits = self::DEFAULT_DIGITS): string
    {
        $key = self::base32Decode($secretBase32);
        $counterBin = pack('N*', 0) . pack('N*', $counter); // 8 bytes big-endian (32+32 bits, counter always fits in the second half)
        $hash = hash_hmac('sha1', $counterBin, $key, true);
        $offset = ord($hash[19]) & 0x0F;
        $truncated = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);
        $code = $truncated % (10 ** $digits);
        return str_pad((string) $code, $digits, '0', STR_PAD_LEFT);
    }

    /** RFC 6238 TOTP = HOTP with a time-derived counter. */
    public static function totp(
        string $secretBase32,
        ?int $timestamp = null,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS
    ): string {
        $timestamp = $timestamp ?? time();
        $counter = (int) floor($timestamp / max(1, $period));
        return self::hotp($secretBase32, $counter, $digits);
    }

    /**
     * Is this code valid right now? Checks a window of steps around the
     * current one (default ±1 = up to 30s of clock drift in either
     * direction) to tolerate a slightly out-of-sync phone clock without
     * opening a window wide enough to make brute-forcing easier. Uses
     * hash_equals() to avoid timing attacks.
     */
    public static function verify(
        string $secretBase32,
        string $code,
        int $window = 1,
        ?int $timestamp = null,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS
    ): bool {
        $code = trim($code);
        if ($code === '' || !preg_match('/^\d+$/', $code)) {
            return false;
        }
        $timestamp = $timestamp ?? time();
        $counter = (int) floor($timestamp / max(1, $period));
        for ($i = -$window; $i <= $window; $i++) {
            $expected = self::hotp($secretBase32, $counter + $i, $digits);
            if (hash_equals($expected, $code)) {
                return true;
            }
        }
        return false;
    }

    /** Standard otpauth:// URI, for a QR code or for pasting into an authenticator app. */
    public static function provisioningUri(string $secretBase32, string $accountLabel, string $issuer): string
    {
        $label = rawurlencode($issuer . ':' . $accountLabel);
        $params = http_build_query([
            'secret' => $secretBase32,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::DEFAULT_DIGITS,
            'period' => self::DEFAULT_PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);
        return 'otpauth://totp/' . $label . '?' . $params;
    }
}

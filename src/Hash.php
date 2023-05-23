<?php

declare(strict_types=1);

namespace Effectra\Security;

/**
 * Class Hash
 *
 * This class provides utility methods for hashing and verifying data.
 *
 * @package Effectra\Security
 */
class Hash
{
    /**
     * The default hashing algorithm.
     *
     * @var string
     */
    protected static $algo = 'sha256';

    /**
     * Generates a hash value using HMAC.
     *
     * @param string $data The data to be hashed.
     * @param string $key The secret key used for hashing.
     * @param bool $binary Whether to return the binary representation of the hash.
     * @return string The generated hash value.
     */
    public static function set(string $data, string $key, bool $binary = false)
    {
        return hash_hmac(static::$algo, $data, $key, $binary);
    }

    /**
     * Verifies if a token matches the expected hash value.
     *
     * @param string $token The token to be verified.
     * @param string $expected The expected hash value.
     * @return bool True if the token matches the expected hash, false otherwise.
     */
    public static function verify(string $token, string $expected)
    {
        return hash_equals($token, $expected);
    }

    /**
     * Sets a password using the specified hash algorithm.
     *
     * @param string $value The password to be hashed.
     * @param int $hash_type The algorithm used for hashing (default: PASSWORD_BCRYPT).
     * @return string The hashed password.
     */
    public static function setPassword(string $value, $hash_type = PASSWORD_BCRYPT): string
    {
        return password_hash($value, $hash_type);
    }

    /**
     * Verifies if a password matches the given hash.
     *
     * @param string $password The password to be verified.
     * @param string $hash The hash to compare against.
     * @return bool True if the password matches the hash, false otherwise.
     */
    public static function verifyPassword(string $password, string $hash)
    {
        return password_verify($password, $hash);
    }
}


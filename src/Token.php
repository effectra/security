<?php

declare(strict_types=1);

namespace Effectra\Security;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

/**
 * Class Token
 *
 * This class provides functionality for generating and validating tokens with Json Web Token.
 *
 * @package Effectra\Security
 */
class Token
{

    public  $config;

    public function config(object $config): self
    {
        $this->config = $config;

        return $this;
    }

    public function getConfig()
    {
        return $this->config;
    }

    public function issuedAt($time): self
    {
        $this->config->issued_at = $time;

        return $this;
    }

    public function expirationTime($time): self
    {
        $this->config->expirationTime = $time;

        return $this;
    }

    public function issuer($issuer): self
    {
        $this->config->issuer = $issuer;

        return $this;
    }
    /**
     * Generates a JSON Web Token (JWT) with the provided data and configuration.
     *
     * @param mixed $data The data to be encoded in the token.
     * @return string The generated JWT.
     */
    public function set(mixed $data): string
    {
        $token = array(
            "iat" => $this->config->issued_at,
            "exp" => $this->config->expirationTime,
            "iss" => $this->config->issuer,
            "data" => $data
        );
        return JWT::encode($token, $this->config->key, 'HS256');
    }

    /**
     * Decodes and verifies a JSON Web Token (JWT) using the provided token and configuration.
     *
     * @param string $token The JWT to be decoded.
     * @param object $config The configuration object containing the token settings.
     * @return stdClass The decoded token as an object.
     */
    public function get(string $token): stdClass
    {
        return JWT::decode($token, new Key($this->config->key, 'HS256'));
    }

    /**
     * Validates the time constraints of a decoded JSON Web Token (JWT).
     *
     * @param stdClass $tokenDecoded The decoded token object.
     * @return bool True if the token is within the valid time range, false otherwise.
     */
    public function validateTime(stdClass $tokenDecoded): bool
    {
        try {
            if ($tokenDecoded->iat > time() || $tokenDecoded->exp < time()) {
                return false;
            }
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Generates a random token of the specified length.
     *
     * @param int $length The length of the token.
     * @return string The generated token.
     */
    public static function generateToken(int $length): string
    {
        return bin2hex(random_bytes($length));
    }

    /**
     * Generate a random integer token of the specified length.
     *
     * @param int $length The length of the token. Default is 10.
     * @return int The generated random integer token.
     * @throws Exception If a random number cannot be generated.
     */
    public static function generateTokenInt(int $length = 10): int
    {
        $min = (int) pow(10, $length - 1);
        $max = (int) pow(10, $length) - 1;

        try {
            return random_int($min, $max);
        } catch (Exception $e) {
            throw new Exception('Failed to generate a random number.', 0, $e);
        }
    }
}

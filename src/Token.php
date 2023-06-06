<?php

declare(strict_types=1);

namespace Effectra\Core\Security;

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

    /**
     * Generates a JSON Web Token (JWT) with the provided data and configuration.
     *
     * @param mixed $data The data to be encoded in the token.
     * @param object $config The configuration object containing the token settings.
     * @return string The generated JWT.
     */
    public function set(mixed $data, $config): string
    {
        $token = array(
            "iat" => $config->issued_at,
            "exp" => $config->expirationTime,
            "iss" => $config->issuer,
            "data" => $data
        );
        return JWT::encode($token, $config->key, 'HS256');
    }
    
    /**
     * Decodes and verifies a JSON Web Token (JWT) using the provided token and configuration.
     *
     * @param string $token The JWT to be decoded.
     * @param object $config The configuration object containing the token settings.
     * @return stdClass The decoded token as an object.
     */
    public function get(string $token, $config): stdClass
    {
        return JWT::decode($token, new Key($config->key, 'HS256'));
    }
   
    /**
     * Validates the time constraints of a decoded JSON Web Token (JWT).
     *
     * @param stdClass $tokenDecoded The decoded token object.
     * @return bool True if the token is within the valid time range, false otherwise.
     */
    public function validateTime(stdClass $tokenDecoded) : bool
    {
        if ($tokenDecoded->iat > time() || $tokenDecoded->exp < time())
        {
            return false;
        }
        return true;
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
}

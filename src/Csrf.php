<?php

declare(strict_types=1);

namespace Effectra\Security;

use Effectra\Session\Contracts\SessionInterface;

/**
 * Class Csrf
 *
 * This class provides functionality for generating and validating CSRF tokens.
 *
 * @package Effectra\Security
 */
class Csrf
{
    /**
     * The URL of the current request.
     *
     * @var string
     */
    private $url = '/';

    /**
     * The label used for the CSRF token in the HTML form.
     *
     * @var string
     */
    private $formTokenLabel = 'eg-csrf-token-label';

    /**
     * The label used for the CSRF token in the session.
     *
     * @var string
     */
    private $sessionTokenLabel = 'EG_CSRF_TOKEN_SESS_IDX';

    /**
     * The POST data.
     *
     * @var array
     */
    private $post = [];

    /**
     * The SERVER data.
     *
     * @var array
     */
    private $server = [];

    /**
     * The URLs to exclude from CSRF token validation.
     *
     * @var array
     */
    private $excludeUrl = [];

    /**
     * The hashing algorithm used for generating the CSRF token.
     *
     * @var string
     */
    private $hashAlgo = 'sha256';

    /**
     * Flag indicating whether to include the IP address in the HMAC calculation.
     *
     * @var bool
     */
    private $hmac_ip = true;

    /**
     * The data used for HMAC calculation.
     *
     * @var string
     */
    private $hmacData = 'ABCeNBHVe3kmAqvU2s7yyuJSF2gpxKLC';

    /**
     * Csrf constructor.
     *
     * @param SessionInterface $session The session object.
     * @param array|null $excludeUrl The URLs to exclude from CSRF token validation.
     * @param array|null &$post The POST data.
     * @param array|null &$server The SERVER data.
     */
    public function __construct(
        protected SessionInterface $session,
        ?array $excludeUrl = null,
        ?array &$post = null,
        ?array &$server = null
    ) {
        $this->session->start();

        if (!is_null($excludeUrl)) {
            $this->excludeUrl = $excludeUrl;
        }

        if (!is_null($post)) {
            $this->post = &$post;
        } else {
            $this->post = &$_POST;
        }

        if (!is_null($server)) {
            $this->server = &$server;
        } else {
            $this->server = &$_SERVER;
        }
    }

    /**
     * Inserts a hidden CSRF token input field in the HTML form.
     *
     * @return string The HTML representation of the hidden input field.
     */
    public function insertHiddenToken()
    {
        $csrfToken = $this->getCSRFToken();

        return "<!--\n--><input type=\"hidden\"" . " name=\"" . $this->xssafe($this->formTokenLabel) . "\"" . " value=\"" . $this->xssafe($csrfToken) . "\"" . " />";
    }

    /**
     * XSS-safe encoding of data.
     *
     * @param string $data The data to be encoded.
     * @param string $encoding The character encoding to use (default: UTF-8).
     * @return string The encoded data.
     */
    public function xssafe($data, $encoding = 'UTF-8')
    {
        return htmlspecialchars($data, ENT_QUOTES | ENT_HTML401, $encoding);
    }

    /**
     * Generates or retrieves the CSRF token.
     *
     * @return string The CSRF token.
     */
    public function getCSRFToken()
    {
        if ($this->session->has($this->sessionTokenLabel) == false) {
            $this->session->put($this->sessionTokenLabel, bin2hex(openssl_random_pseudo_bytes(32)));
        }

        if ($this->hmac_ip !== false) {
            $token = $this->hMacWithIp($this->session->get($this->sessionTokenLabel));
        } else {
            $token = $this->session->get($this->sessionTokenLabel);
        }

        return $token;
    }

    /**
     * Generates an HMAC value with IP address.
     *
     * @param string $token The token to be hashed.
     * @return string The HMAC value.
     */
    private function hMacWithIp($token): string
    {
        $hashHmac = \hash_hmac($this->hashAlgo, $this->hmacData, $token);
        return $hashHmac;
    }

    /**
     * Retrieves the URL of the current request.
     *
     * @return string The URL of the current request.
     */
    private function getCurrentRequestUrl()
    {
        return $this->url;
    }

    /**
     * Sets the URL of the current request.
     *
     * @param string $url The URL of the current request.
     */
    public function setUrl(string $url)
    {
        $this->url = $url;
    }

    /**
     * Validates the CSRF token for the current request.
     *
     * @return bool True if the CSRF token is valid, false otherwise.
     */
    public function validate()
    {
        $isValid = false;
        $currentUrl = $this->getCurrentRequestUrl();

        if (!in_array($currentUrl, $this->excludeUrl)) {
            if (!empty($this->post)) {
                $isValid = $this->validateRequest();
            }
        }

        return $isValid;
    }

    /**
     * Validates the CSRF token for the current request.
     *
     * @return bool True if the CSRF token is valid, false otherwise.
     */
    public function validateRequest()
    {
        if ($this->session->has($this->sessionTokenLabel) == false) {
            // CSRF Token not found
            return false;
        }

        if (!empty($this->post[$this->formTokenLabel])) {
            // Let's pull the POST data
            $token = $this->post[$this->formTokenLabel];
        } else {
            return false;
        }

        if (!is_string($token)) {
            return false;
        }

        // Grab the stored token
        if ($this->hmac_ip !== false) {
            $expected = $this->hMacWithIp($this->session->get($this->sessionTokenLabel));
        } else {
            $expected = $this->session->get($this->sessionTokenLabel);
        }

        return \hash_equals($token, $expected);
    }

    /**
     * Removes the CSRF token from the session.
     */
    public function unsetToken()
    {
        if (!empty($this->session->get($this->sessionTokenLabel))) {
            $this->session->forget($this->sessionTokenLabel);
        }
    }
}


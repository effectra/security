# Effectra Security

Effectra\Security is a PHP library that provides security-related functionalities such as hashing, password management, CSRF token handling, and token generation.

## Features

- Hashing: Securely hash data using various algorithms.
- Password Management: Generate and verify hashed passwords.
- CSRF Protection: Generate and validate CSRF tokens for web applications.
- Token Generation: Create and decode JSON Web Tokens (JWT).

## Requirements

- PHP 7.0 or higher

## Installation

You can install the Effectra\Security library via Composer. Run the following command in your project directory:

```bash
composer require effectra/security
```

## Usage

### Hashing

The `Effectra\Security\Hash` class provides methods for hashing data using HMAC algorithms.

Example usage:

```php
use Effectra\Security\Hash;

$data = 'Hello, World!';
$key = 'secret-key';

$hash = Hash::set($data, $key);
echo "Hashed value: " . $hash;
```

### Password Management

The `Effectra\Security\Hash` class also includes methods for securely managing passwords.

Example usage:

```php
use Effectra\Security\Hash;

$password = 'password123';

$hashedPassword = Hash::setPassword($password);
echo "Hashed password: " . $hashedPassword;

$isPasswordValid = Hash::verifyPassword($password, $hashedPassword);
if ($isPasswordValid) {
    echo "Password is valid.";
} else {
    echo "Password is invalid.";
}
```

### CSRF Protection

The `Effectra\Security\Csrf` class provides functionality for generating and validating CSRF tokens.

Example usage:

```php
use Effectra\Security\Csrf;
use Effectra\Session\Session; // Replace with your own session implementation

// Initialize the CSRF class with a session instance
$session = new Session();
$csrf = new Csrf($session);

// Generate and insert a CSRF token in your HTML form
$html = '<form>';
$html .= $csrf->insertHiddenToken();
$html .= '<input type="submit" value="Submit">';
$html .= '</form>';

echo $html;

// Validate the CSRF token on form submission
if ($csrf->validate()) {
    echo "CSRF token is valid.";
} else {
    echo "CSRF token is invalid.";
}
```

### Token Generation

The `Effectra\Security\Token` class allows you to generate and decode JSON Web Tokens (JWT).

Example usage:

```php
use Effectra\Security\Token;

$data = ['user_id' => 123];

$config = (object) [
    'issued_at' => time(),
    'expirationTime' => time() + 3600, // Expiration time 1 hour from now
    'issuer' => 'example.com',
    'key' => 'your-secret-key'
];

$token = new Token();
$encodedToken = $token->set($data, $config);
echo "Encoded token: " . $encodedToken;

$decodedToken = $token->get($encodedToken, $config);
echo "Decoded token: ";
print_r($decodedToken);
```

## Contributing

Contributions are welcome! Feel free to submit bug reports, feature requests, or pull requests on the [GitHub repository](https://github.com/effectra/security).

## License

Effectra\Security is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Credits

Effectra\Security is developed and maintained by [Effectra](https://www.effectra.com).


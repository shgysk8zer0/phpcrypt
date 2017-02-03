# PHPCrypt
[![Build Status](https://travis-ci.org/shgysk8zer0/phpcrypt.svg?branch=master)](https://travis-ci.org/shgysk8zer0/phpcrypt)
> Provides easy to use classes and traits for cryptographic functions using `openssl_*`. Intended
> to be compatible with [JSCrypt](https://github.com/shgysk8zer0/JSCrypt) &
> [SubtleCrypto / JWK](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey)

## Requires:
-   **PHP >= 7**
-   [openssl](https://secure.php.net/manual/en/book.openssl.php)

## Installation:
-   Best if imported as a Git submodule using [`git submodule add git://github.com/shgysk8zer0/phpcrypt.git`](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
-   Use [`spl_autoload`](https://secure.php.net/manual/en/function.spl-autoload-register.php) for autoloading

## Provided classes:
-   [`PublicKey`](https://github.com/shgysk8zer0/phpcrypt/blob/master/publickey.php)
-   [`PrivateKey`](https://github.com/shgysk8zer0/phpcrypt/blob/master/privatekey.php)
-   [`KeyPair`](https://github.com/shgysk8zer0/phpcrypt/blob/master/keypair.php)
-   [`FormSign`](https://github.com/shgysk8zer0/phpcrypt/blob/master/formsign.php)

## Provided traits:
-   [`Traits\KeyPair`](https://github.com/shgysk8zer0/phpcrypt/blob/master/traits/keypair.php)
-   [`Traits\AES`](https://github.com/shgysk8zer0/phpcrypt/blob/master/traits/aes.php)
-   [`Traits\Password`](https://github.com/shgysk8zer0/phpcrypt/blob/master/traits/password.php)

## Provided interfaces:
-   [`Interfaces\Key`](https://github.com/shgysk8zer0/phpcrypt/blob/master/interfaces/key.php)

### Example code:
```php
<?php
set_include_path('/path/to/classes_dir/' . PATH_SEPARATOR . get_include_path());
spl_autoload_register('spl_autoload');

$keys = new \shgysk8zer0\PHPCrypt\KeyPair(PUBLIC_KEY, PRIVATE_KEY, PASSWORD);

$encrypted = $keys->encrypt(MESSAGE);
$decrypted = $keys->decrypt($encrypted);
$sig       = $keys->sign($encrypted);
$valid     = $keys->verify($encrypted, $sig);
$matches   = MESSAGE === $decrypted;
```

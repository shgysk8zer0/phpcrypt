<?php
declare(strict_types=1);
/**
 * @author Chris Zuber
 * @package shgysk8zer0\PHPCrypt
 * @subpackage Traits
 * @version 1.0.0
 * @copyright 2017, Chris Zuber
 * @license http://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
namespace shgysk8zer0\PHPCrypt\Traits;

/**
 * Provides easy, object-oriented methods for public key cryptography
 * @example:
 * if (! @ file_exists(PUBLIC_KEY) or ! @file_exists(PRIVATE_KEY)) {
 *	$keys = PKey::genKeys(PASSWORD);
 *	file_put_contents(PRIVATE_KEY, $keys['private']);
 *	file_put_contents(PUBLIC_KEY,  $keys['public']);
 *	unset($keys);
 * }

 * $pkey      = new PKey();
 * $pkey->setPrivateKey(PRIVATE_KEY[, PASSWORD]);
 * $pkey->setPublicKey(PUBLIC_KEY);
 *
 * $encrypted = $pkey->publicEncrypt(MESSAGE);
 * $decrypted = $pkey->privateDecrypt($encrypted);
 * $sig       = $pkey->sign($encrypted);
 * $valid     = $pkey->verify($encrypted, $sig);

 * if ($valid) {
 *	echo 'Valid signature.' . PHP_EOL;
 * } else {
 *	echo 'Invalid signature.'  . PHP_EOL;
 * }

 * if ($decrypted === MESSAGE) {
 *	echo $decrypted . PHP_EOL;
 * } else {
 *	echo 'Decrypted message does not match original message.' . PHP_EOL;
 * }
 */
trait Pkey
{
	/**
	 * The private key
	 * @var Resource
	 */
	private $_private_key;

	/**
	 * The public key
	 * @var Resource
	 */
	private $_public_key;

	/**
	 * Imports and sets private key
	 * @param  String $key      File to obtain private key from
	 * @param  string $password Optional password to decrypt the key
	 * @return Bool             Whether or not the key was successfully imported
	 */
	final public function setPrivateKey($key, $password = null)
	{
		if ($this->_private_key = $this->_importPrivateKey($key, $password)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Imports and sets public key
	 * @param  String $key File to obtain the public key from
	 * @return Bool        Whether or not the key was successfully imported
	 */
	final public function setPublicKey($key)
	{
		if ($this->_public_key = $this->_importPublicKey($key)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Encrypt $data using public key
	 * @param  String  $data    The data to encrypt using public key
	 * @param  String  $public_key Optional public key to check against. Defaults to $_public_key
	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
	 * @return String           Data encrypted using public key
	 * @see https://php.net/manual/en/function.openssl-public-encrypt.php
	 */
	final public function publicEncrypt($data, $public_key = null, $padding = OPENSSL_PKCS1_OAEP_PADDING)
	{
		if (is_null($public_key)) {
			if (!isset($this->_public_key)) {
				throw new \Exception('Attempting to encrypt using unset public key.');
			} else {
				$public_key = $this->_public_key;
			}
		} else {
			$public_key = $this->_importPublicKey($public_key);
		}

		if (openssl_public_encrypt($data, $crypted, $public_key, $padding)) {
			return $crypted;
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
	 * Decrypt data using public key
	 * @param  String  $data    The encrypted data
	 * @param  String  $public_key Optional public key to check against. Defaults to $_public_key
	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
	 * @return String           Data decrypted using public key
	 * @see https://php.net/manual/en/function.openssl-public-decrypt.php
	 */
	final public function publicDecrypt($data, $public_key = null, $padding = OPENSSL_PKCS1_OAEP_PADDING)
	{
		if (is_null($public_key)) {
			if (!isset($this->_public_key)) {
				throw new \Exception('Attempting to decrypt using unset public key.');
			} else {
				$public_key = $this->_public_key;
			}
		} else {
			$public_key = $this->_importPublicKey($public_key);
		}

		if (openssl_public_decrypt($data, $decrypted, $public_key, $padding)) {
			return $decrypted;
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
	 * Encrypt data using private key
	 * @param  String  $data    The data to encrypt using private key
	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
	 * @return String           Data encryped with private key
	 * @see https://php.net/manual/en/function.openssl-private-encrypt.php
	 */
	final public function privateEncrypt($data, $padding = OPENSSL_PKCS1_OAEP_PADDING)
	{
		if (!isset($this->_private_key)) {
			throw new \Exception('Attempting to encrypt using unset private key.');
		}
		if (openssl_private_encrypt($data, $crypted, $this->_private_key, $padding)) {
			return $crypted;
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
	 * Decrypt data using private key
	 * @param  String  $data    The data to encrypt with the private key
	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
	 * @return String           Data encrypted with private key
	 * @see https://php.net/manual/en/function.openssl-private-decrypt.php
	 */
	final public function privateDecrypt($data, $padding = OPENSSL_PKCS1_OAEP_PADDING)
	{
		if (!isset($this->_private_key)) {
			throw new \Exception('Attempting to decrypt using unset private key.');
		}
		if (openssl_private_decrypt($data, $decrypted, $this->_private_key, $padding)) {
			return $decrypted;
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
	 * Sign $data using private key
	 * @param  String  $data The data to sign using private key
	 * @param  integer $algo Signing algorithm constant <https://secure.php.net/manual/en/openssl.signature-algos.php>
	 * @return String        Signature created using private key
	 * @see https://php.net/manual/en/function.openssl-sign.php
	 */
	final public function sign($data, $algo = OPENSSL_ALGO_SHA512)
	{
		if (!isset($this->_private_key)) {
			throw new \Exception('Attempting to sign using unset private key.');
		}
		if (openssl_sign($data, $sig, $this->_private_key, $algo)) {
			return $sig;
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
	 * Verify a signature using a public key
	 * @param  String  $data       The original data
	 * @param  String  $sig        The signature
	 * @param  String  $public_key Optional public key to check against. Defaults to $_public_key
	 * @param  integer $algo Signing algorithm constant <https://secure.php.net/manual/en/openssl.signature-algos.php>
	 * @return Bool          Whether or not the signature is valid
	 * @see https://php.net/manual/en/function.openssl-sign.php
	 */
	final public function verify(
		$data,
		$sig,
		$public_key = null,
		$algo       = OPENSSL_ALGO_SHA512
	)
	{
		if (is_null($public_key)) {
			if (!isset($this->_public_key)) {
				throw new \Exception('Attempting to verify signature using unset public key.');
			} else {
				$public_key = $this->_public_key;
			}
		} else {
			$public_key = $this->_importPublicKey($public_key);
		}

		$valid = openssl_verify($data, $sig, $public_key, $algo);
		if ($valid === 1) {
			return true;
		} elseif ($valid === 0) {
			return false;
		} else {
			trigger_error(openssl_error_string());
			return false;
		}
	}

	/**
	 * Generates a new private/public key pair
	 * @param  string   $password Optional password to encrypt the private key
	 * @param  string   $digest   Hashing method to use
	 * @param  integer  $length   Size of key
	 * @param  integer  $keytype  Key type constant <https://secure.php.net/manual/en/openssl.key-types.php>
	 * @param  integer  $cipher   Cipher to use when encrypting private key usign $password <https://secure.php.net/manual/en/openssl.ciphers.php>
	 * @return Array              ['private' => $private_key, 'public' => $pubic_key]
	 * @see https://secure.php.net/manual/en/function.openssl-pkey-new.php
	 */
	final public static function genKeys(
		$password   = null,
		$digest     = 'sha512',
		$length     = 4096,
		$keytype    = OPENSSL_KEYTYPE_RSA,
		$cipher     = OPENSSL_CIPHER_AES_256_CBC
	)
	{
		$configargs = [
			'digest_alg'       => $digest,
			'private_key_bits' => $length,
			'private_key_type' => $keytype,
		];

		if (is_string($password)) {
			$configargs['encrypt_key'] = true;
			$configargs['encrypt_key_cipher'] = $cipher;
		}

		$res = openssl_pkey_new($configargs);

		if (!$res) {
			throw new \Exception(openssl_error_string());
		}
		$public = openssl_pkey_get_details($res);

		openssl_pkey_export($res, $private, $password, $configargs);

		return [
			'private' => $private,
			'public'  => $public['key']
		];
	}

	/**
	 * Import public key from file or a PEM formatted public key string
	 * @param  String $key   '/path/to/key.pem' or '-----BEGIN PUBLIC KEY-----' ...
	 * @return Resource      A positive key resource identifier
	 * @see https://php.net/manual/en/function.openssl-pkey-get-public.php
	 */
	final public function importPublicKey($key)
	{
		if (@file_exists($key)) {
			$key = 'file://' . realpath($key);
		}

		if ($key = @openssl_pkey_get_public($key)) {
			return $key;
		} else {
			throw new \InvalidArgumentException(openssl_error_string());
			return false;
		}
	}

	/**
	 * Import private key from file or a PEM formatted private key string
	 * @param  String $key      '/path/to/key.pem' or '-----BEGIN [ENCRYPTED ]PRIVATE KEY-----' ...
	 * @param  String $password Optional password to unlock an encrypted private key
	 * @return Resource         A positive key resource identifier
	 * @see https://secure.php.net/manual/en/function.openssl-pkey-get-private.php
	 */
	final public function importPrivateKey($key, $password = null)
	{
		if (@file_exists($key)) {
			$key = 'file://' . realpath($key);
		}

		if ($key = @openssl_pkey_get_private($key, $password)) {
			return $key;
		} else {
			throw new \InvalidArgumentException(openssl_error_string());
			return false;
		}
	}
}

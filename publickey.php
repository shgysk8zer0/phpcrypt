<?php
/**
 * @author Chris Zuber
 * @package shgysk8zer0\PHPCrypt
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
namespace shgysk8zer0\PHPCrypt;

/**
 * A collection of openssl_* functions for public keys
 */
final class PublicKey extends Abstracts\Key
{
	/**
	 * Returns tha SHA-256 hash of the public key
	 * @return string SHA-256
	 */
	final public function __toString(): String
	{
		return hash('sha256', $this->export());
	}

	/**
	 * Import public key from string
	 * @param  String $data "-----BEGIN PUBLIC KEY-----...."
	 * @return self         Imported PublicKey
	 * @see https://php.net/manual/en/function.openssl-pkey-get-public.php
	 */
	public static function import(String $data): self
	{
		if ($key = @openssl_pkey_get_public($data)) {
			return new self($key);
		} else {
			throw new \InvalidArgumentException(openssl_error_string());
		}
	}

	/**
	 * Import a public key form a file
	 * @param  String        $filename /path/to/key.pem
	 * @return self          Imported PublicKey
	 * @see https://php.net/manual/en/function.openssl-pkey-get-public.php
	 */
	final public static function importFromFile(String $filename): self
	{
		if (@file_exists($filename)) {
			$filename = 'file://' . realpath($filename);
			if ($key = @openssl_pkey_get_public($filename)) {
				return new self($key);
			} else {
				throw new \InvalidArgumentException(openssl_error_string());
			}
		} else {
			throw new \InvalidArgumentException("$filename not found.");
		}
	}

	/**
 	 * Encrypt $data using public key.
 	 * Can be decrypted by matching private key
 	 * @param  String  $data    The data to encrypt using public key
	 * @param  boolean $raw     Whether or not to use binary output
 	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
 	 * @return String           Data encrypted using public key
 	 * @see https://php.net/manual/en/function.openssl-public-encrypt.php
 	 */
	public function encrypt(
		String $data,
		Bool   $raw     = false,
		Int    $padding = OPENSSL_PKCS1_OAEP_PADDING
	): String
	{
		if (openssl_public_encrypt($data, $crypted, $this->_key, $padding)) {
			return $raw ? $crypted : base64_encode($crypted);
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
 	 * Decrypt data using public key
 	 * @param  String  $data    Data encrypted by matching private key
	 * @param  boolean $raw     Whether or not to use binary output
 	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
 	 * @return String           Data decrypted using public key
 	 * @see https://php.net/manual/en/function.openssl-public-decrypt.php
 	 */
	public function decrypt(
		String $data,
		Bool   $raw    = false,
		Int   $padding = OPENSSL_PKCS1_OAEP_PADDING
	): String
	{
		if (openssl_public_decrypt($raw ? $data : base64_decode($data), $decrypted, $this->_key, $padding)) {
			return $decrypted;
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
 	 * Verify a signature using a public key
 	 * @param  String  $data       The original data
 	 * @param  String  $sig        The signature
 	 * @param  boolean $raw        Whether or not to use binary output
 	 * @param  String  $public_key Optional public key to check against. Defaults to $_public_key
 	 * @param  integer $algo       Signing algorithm constant <https://secure.php.net/manual/en/openssl.signature-algos.php>
 	 * @return Bool          Whether or not the signature is valid
 	 * @see https://php.net/manual/en/function.openssl-sign.php
 	 */
	public function verify(
		String $data,
		String $sig,
		Bool   $raw  = false,
		Int    $algo = OPENSSL_ALGO_SHA512
	): Bool
	{
		$valid = openssl_verify($data, $raw ? $sig : base64_decode($sig), $this->_key, $algo);
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
	 * Export the contents of the key as a string
	 * @return String "-----BEGIN PUBLIC KEY-----...."
	 */
	public function export(): String
	{
		return openssl_pkey_get_details($this->_key)['key'];
	}

	/**
	 * Export the key to file
	 * @param  String $filename /path/to/key.pem
	 * @return Bool             Whether or not it saved successfully
	 */
	public function exportToFile(String $filename): Bool
	{
		return is_int(file_put_contents($filename, $this->export()));
	}
}

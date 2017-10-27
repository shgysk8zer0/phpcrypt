<?php
declare(strict_types=1);
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
final class PrivateKey extends Abstracts\Key
{
	/**
	 * Import a private key from string
	 * @param  String $data     '-----BEGIN [ENCRYPTED ]PRIVATE KEY-----'
	 * @param  String $password Option password to unlock the key
	 * @return self             Imported PrivateKey
	 */
	public static function import(String $data, String $password = null): self
	{
		if ($key = @openssl_pkey_get_private($data, $password)) {
			return new self($key);
		} else {
			throw new \InvalidArgumentException(openssl_error_string());
		}
	}

	/**
	 * Import private key from file
	 * @param  String $filename /path/to/key.pem
	 * @param  String $password Optional password to unlock key
	 * @return self             Imported PrivateKey
	 */
	public static function importFromFile(
		String $filename,
		String $password = null
	): self
	{
		if (@file_exists($filename)) {
			$filename = 'file://' . realpath($filename);
			if ($key = @openssl_pkey_get_private($filename, $password)) {
				return new self($key);
			} else {
				throw new \InvalidArgumentException(openssl_error_string());
			}
		} else {
			throw new \InvalidArgumentException("$filename not found.");
		}

	}

	/**
	* Encrypt $data using private key.
	* Can be decrypted by matching public key
	* @param  String  $data    The data to encrypt using public key
	* @param  boolean $raw     Whether or not to use binary output
	* @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
	* @return String           Data encrypted using private key
	* @see https://php.net/manual/en/function.openssl-private-encrypt.php
	*/
	public function encrypt(
		String $data,
		Bool   $raw     = false,
		Int    $padding = OPENSSL_PKCS1_OAEP_PADDING
	): String
	{
		if (openssl_private_encrypt($data, $crypted, $this->_key, $padding)) {
			return $raw ? $crypted : base64_encode($crypted);
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
 	 * Decrypt data using private key
 	 * @param  String  $data    Data encrypted by matching public key
	 * @param  boolean $raw     Whether or not to use binary output
 	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
 	 * @return String           Data decrypted using public key
 	 * @see https://php.net/manual/en/function.openssl-private-decrypt.php
 	 */
	public function decrypt(
		String $data,
		Bool   $raw     = false,
		Int    $padding = OPENSSL_PKCS1_OAEP_PADDING
	): String
	{
		if (openssl_private_decrypt($raw ? $data : base64_decode($data), $decrypted, $this->_key, $padding)) {
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
	public function sign(
		String $data,
		Bool   $raw  = false,
		Int    $algo = OPENSSL_ALGO_SHA512
	): String
	{
		if (openssl_sign($data, $sig, $this->_key, $algo)) {
			return $raw ? $sig : base64_encode($sig);
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
	 * Export the contents of the key as a string
	 * @param String $password   Optional string to lock the private key with
	 * @param array  $configargs Optional array of configuration paramaters
	 * @return String             '-----BEGIN [ENCRYPTED ]PRIVATE KEY-----'
	 */
	public function export(
		String $password   = null,
		Array  $configargs = self::CONFIGARGS
	): String
	{
		openssl_pkey_export($this->_key, $key, $password, $configargs);
		return $key;
	}

	/**
	 * Export the key to file
	 * @param  String $filename   /path/to/key.pem
	 * @param  String $password   Optional password to lock the key
	 * @param  Array  $configargs Optional array of configuration paramaters
	 * @return Bool               Whether or not it saved successfully
	 */
	public function exportToFile(
		String $filename,
		String $password   = null,
		Array  $configargs = self::CONFIGARGS
	): Bool
	{
		return openssl_pkey_export_to_file($this->_key, $filename, $password, $configargs);
	}
}

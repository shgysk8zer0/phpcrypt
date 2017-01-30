<?php
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

trait AES
{
	/**
	 * openssl_encrypt — Encrypts data
	 * @param  String   $data     The data
	 * @param  String   $password The password
	 * @param  String   $method   The cipher <https://secure.php.net/manual/en/function.openssl-get-cipher-methods.php>
	 * @param  integer  $options  A bitwise disjunction of the flags OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING
	 * @return String             "$algo:$iv:$encrypted"
	 * @see https://secure.php.net/manual/en/function.openssl-encrypt.php
	 */
	final public function encrypt(
		String $data,
		String $password,
		String $method    = 'AES-256-CBC',
		String $hash_algo = 'sha512',
		Int $options      = 0
	) : String
	{
		if (! in_array($hash_algo, hash_algos())) {
			trigger_error("Unsupported hash algorithm: $hash_algo");
			return '';
		} elseif (! in_array($method, openssl_get_cipher_methods())) {
			trigger_error("Unsupported cipher method: $method");
		}

		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));

		$password = hash($hash_algo, $password);

		$encrypted = openssl_encrypt($data, $method, $password, $options, $iv);

		if (is_string($encrypted)) {
			// Append the intialization vector as hex to the encrypted data
			// This is necessary to be able to obtain it for decrypting.
			// It is not sensitive data, so there is no harm in appending it
			return join(':', [
				base64_encode($hash_algo),
				base64_encode($iv),
				$encrypted
			]);
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}

	/**
	 * openssl_encrypt — Decrypts data
	 * @param  String   $data     "$algo:$iv:$encrypted"
	 * @param  String   $password The password
	 * @param  String   $method   The cipher <https://secure.php.net/manual/en/function.openssl-get-cipher-methods.php>
	 * @param  integer  $options  A bitwise disjunction of the flags OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING
	 * @return String             The decrypted string
	 * @see https://secure.php.net/manual/en/function.openssl-decrypt.php
	 */
	final public function decrypt(
		String $data,
		String $password,
		String $method  = 'AES-256-CBC',
		Int $options    = 0
	) : String
	{
		// Should be in the form $algo:$iv$encrypted
		list($algo, $iv, $encrypted) = array_pad(explode(':', $data, 3), 3, null);
		unset($data);

		if (! isset($algo, $iv, $encrypted)) {
			trigger_error('Trying to decrypt a string that does not contain necessary data.');
			return '';
		}

		$algo = base64_decode($algo);
		$iv   = base64_decode($iv);

		if (! in_array($algo, hash_algos())) {
			trigger_error("Unsupported hash algorithm: $algo");
			return '';
		} elseif (strlen($iv) !== openssl_cipher_iv_length($method)) {
			trigger_error('Invalid intialization vector length.');
			return '';
		} elseif (! in_array($method, openssl_get_cipher_methods())) {
			trigger_error("Unsupported cipher method: $method");
		}

		$password = hash($algo, $password);
		$decrypted = openssl_decrypt($encrypted, $method, $password, $options, $iv);

		if (is_string($decrypted)) {
			return $decrypted;
		} else {
			trigger_error(openssl_error_string());
			return '';
		}
	}


}

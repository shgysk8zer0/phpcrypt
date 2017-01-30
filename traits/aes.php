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
	 * @param  String   $data      The data
	 * @param  String   $password  The password
	 * @param  String   $cipher    The cipher <https://secure.php.net/manual/en/function.openssl-get-cipher-methods.php>
	 * @param  String   $hash_algo Password hashing algorith <https://secure.php.net/manual/en/function.hash-algos.php>
	 * @param  integer  $options   A bitwise disjunction of the flags OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING
	 * @return String             "$options:$cipher$algo:$iv$encrypted"
	 * @see https://secure.php.net/manual/en/function.openssl-encrypt.php
	 */
	final public function encrypt(
		String $data,
		String $password,
		String $cipher    = 'AES-256-CBC',
		String $hash_algo = 'sha512',
		Int    $options   = 0
	) : String
	{
		// Check that cipher method and hash algorithm are supported
		if (! in_array($hash_algo, hash_algos())) {
			trigger_error("Unsupported hash algorithm: $hash_algo");
			$encrypted = '';
		} elseif (! in_array($cipher, openssl_get_cipher_methods())) {
			trigger_error("Unsupported cipher method: $cipher");
			$encrypted = '';
		} else {
			// Get the appropriate initialization vector for cipher
			$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));
			// Hash the password using selected algorithm
			$password = hash($hash_algo, $password);
			// Get encrypted data
			$encrypted = openssl_encrypt($data, $cipher, $password, $options, $iv);

			if (is_string($encrypted)) {
				// Convert into format "$options:$cipher$algo:$iv$encrypted"
				$encrypted = join(':', [
					$options,
					base64_encode($cipher),
					base64_encode($hash_algo),
					base64_encode($iv),
					$encrypted
				]);
			} else {
				trigger_error(openssl_error_string());
				$encrypted = '';
			}
		}

		return $encrypted;
	}

	/**
	 * openssl_encrypt — Decrypts data
	 * @param  String   $encrypted "$option:$cipher$algo:$iv$encrypted"
	 * @param  String   $password  The password
	 * @return String              The decrypted string
	 * @see https://secure.php.net/manual/en/function.openssl-decrypt.php
	 */
	final public function decrypt(
		String $encrypted,
		String $password
	) : String
	{
		// Should be in the form $options:$cipher$algo:$iv$encrypted
		// Get decryption paramaters from the string itself
		$encrypted = array_pad(explode(':', $encrypted, 5), 5, null);
		list($options, $cipher, $algo, $iv, $encrypted) = $encrypted;

		// Check that all required paramaters are set
		if (! isset($options, $cipher, $algo, $iv, $encrypted)) {
			trigger_error('Trying to decrypt a an invalid string.');
			return '';
		}

		// Do necessary conversions to restore original values
		$algo    = base64_decode($algo);
		$iv      = base64_decode($iv);
		$cipher  = base64_decode($cipher);
		$options = intval($options);

		// Check that hash algorithm, cipher, and intialization vector are valid
		if (! in_array($algo, hash_algos())) {
			trigger_error("Unsupported hash algorithm: $algo");
			$decrypted = '';
		} elseif (! in_array($cipher, openssl_get_cipher_methods())) {
			trigger_error("Unsupported cipher method: $cipher");
			$decrypted = '';
		} elseif (strlen($iv) !== openssl_cipher_iv_length($cipher)) {
			trigger_error('Invalid intialization vector length.');
			$decrypted = '';
		} elseif (! in_array($cipher, openssl_get_cipher_methods())) {
			trigger_error("Unsupported cipher method: $cipher");
			$decrypted = '';
		} else {
			// Hash the password using given algorithm
			$password  = hash($algo, $password);

			// Decrypt the data
			$decrypted = openssl_decrypt($encrypted, $cipher, $password, $options, $iv);

			// Check for errors
			if (!is_string($decrypted)) {
				trigger_error(openssl_error_string());
				$decrypted = '';
			}
		}

		return $decrypted;
	}


}

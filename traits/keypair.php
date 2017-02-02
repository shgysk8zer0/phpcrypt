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
namespace shgysk8zer0\PHPCrypt\Traits;

/**
 * A collection of methods for working with private/public keys.
 * See PublicKey & PrivateKey class for more documentation.
 */
trait KeyPair
{
	/**
	 * Generates a new private/public key
	 * @param  String $password   Optional password to lock the private key
	 * @param  Array  $configargs Optional configuration paramaters
	 * @return Array              ['public' => PublicKey, 'private' => PrivateKey]
	 * @see https://php.net/manual/en/function.openssl-pkey-new.php
	 */
	final public static function generateKeyPair(
		String $password    = null,
		Array  $configargs  = \shgysk8zer0\PHPCrypt\Abstracts\Key::CONFIGARGS
	): Array
	{
		if (is_string($password)) {
			$configargs['encrypt_key']        = true;
		} else {
			unset($configargs['encrypt_key_cipher']);
		}

		$res = openssl_pkey_new($configargs);

		if (!$res) {
			throw new \Exception(openssl_error_string());
		}
		$public = openssl_pkey_get_details($res);

		openssl_pkey_export($res, $private, $password, $configargs);

		return [
			'private' => \shgysk8zer0\PHPCrypt\PrivateKey::import($private, $password),
			'public'  => \shgysk8zer0\PHPCrypt\PublicKey::import($public['key'])
		];
	}

	final public function publicEncrypt(...$args): String
	{
		return call_user_func_array([$this->_public_key, 'encrypt'], $args);
	}

	final public function publicDecrypt(...$args): String
	{
		return call_user_func_array([$this->_public_key, 'decrypt'], $args);
	}

	final public function privateEncrypt(...$args): String
	{
		return call_user_func_array([$this->_private_key, 'encrypt'], $args);
	}

	final public function privateDecrypt(...$args): String
	{
		return call_user_func_array([$this->_private_key, 'decrypt'], $args);;
	}

	final public function sign(...$args): String
	{
		return call_user_func_array([$this->_private_key, 'sign'], $args);;
	}

	final public function verify(...$args): Bool
	{
		return call_user_func_array([$this->_public_key, 'verify'], $args);
	}
}

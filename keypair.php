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
 * This class just combines the functionality of PublicKey & PrivateKey classes.
 * Aside from `__construct`, it has no methods of it's own other than to call
 * the appropriate method for the appropriate key.
 *
 * As such, please refer to the key classes for documentation.
 */
class KeyPair implements \JsonSerializable
{
	use Traits\KeyPair;

	/**
	 * The public key
	 * @var PublicKey
	 */
	private $_public_key;

	/**
	 * The private key
	 * @var PrivateKey
	 */
	private $_private_key;

	/**
	 * Creates a new instance by importing public and private keys from files
	 * @param String $public_key  /path/to/public_key.pem
	 * @param String $private_key /path/to/private_key.pem
	 * @param String $password    Optional password to unlock private key
	 */
	public function __construct(
		String $public_key,
		String $private_key,
		String $password = null
	)
	{
		$this->_public_key = @file_exists($public_key)
			? PublicKey::importFromFile($public_key)
			: PublicKey::import($public_key);

		$this->_private_key = @file_exists($private_key)
			? PrivateKey::importFromFile($private_key, $password)
			: PrivateKey::import($privateKey, $password);
	}

	/**
	 * Returns tha SHA-256 hash of the public key
	 * @return string SHA-256
	 */
	public function __toString(): String
	{
		return "{$this->_public_key}";
	}

	/**
	 * Return Key data as a json encoded String
	 * @return Array
	 * @see https://secure.php.net/manual/en/function.openssl-pkey-get-details.php
	 * @todo Make compatible with JWK format
	 */
	public function jsonSerialize()
	{
		return $this->_public_key->jsonSerialize();
	}

	public function __debugInfo()
	{
		return [
			'publicKey'  => $this->_public_key,
			'privateKey' => $this->_private_key,
		];
	}
}

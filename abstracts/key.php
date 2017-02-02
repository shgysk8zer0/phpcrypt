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
namespace shgysk8zer0\PHPCrypt\Abstracts;

/**
 * Abstract class to be extended by PublicKey & PrivateKey
 */
abstract class Key implements \shgysk8zer0\PHPCrypt\Interfaces\Key, \JsonSerializable
{
	const CONFIGARGS = array(
		'digest'  => 'sha512',
		'length'  => 4096,
		'keytype' => OPENSSL_KEYTYPE_RSA,
		'cipher'  => OPENSSL_CIPHER_AES_256_CBC
	);

	/**
	 * Handle for key
	 * @var Resource
	 */
	protected $_key;

	/**
	 * Create a new instance by using Key::import or Key::importFromFile
	 * @param Resource $key Handle for public/private key
	 */
	final protected function __construct($key)
	{
		if (is_resource($key)) {
			$this->_key = $key;
		} else {
			throw new \InvalidArgumentException(sprintf('Expected a resource for a key but got a %s.', gettype($key)));
		}
	}

	/**
	 * Return Key data as a json encoded String
	 * @return Array
	 * @see https://secure.php.net/manual/en/function.openssl-pkey-get-details.php
	 * @todo Make compatible with JWK format
	 */
	public function jsonSerialize(): Array
	{
		return openssl_pkey_get_details($this->_key) ?? [];
	}

	/**
	 * Return Key data for debugging
	 * @return Array
	 * @see https://secure.php.net/manual/en/function.openssl-pkey-get-details.php
	 */
	public function __debugInfo()
	{
		return openssl_pkey_get_details($this->_key) ?? [];
	}
}

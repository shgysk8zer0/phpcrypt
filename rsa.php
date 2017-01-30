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

final class RSA
{
	use Traits\PKey;

	/**
	 * Loads private and public keys, unlocking private key with optional password
	 * @param String $public_key  '/path/to/key.pem' or '-----BEGIN PUBLIC KEY-----' ...
	 * @param String $private_key '/path/to/key.pem' or '-----BEGIN [ENCRYPTED ]PRIVATE KEY-----' ...
	 * @param String $password    Optional password to unlock private key
	 */
	public function __construct(
		String $public_key,
		String $private_key,
		String $password = null
	)
	{
		if (
			! $this->setPrivateKey($private_key, $password)
			or ! $this->setPublicKey($public_key)
		) {
			throw new \InvalidArgumentException('Given files are not valid keys.');
		}
	}
}

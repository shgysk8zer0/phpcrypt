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
 * Provides protected methods for password_* functions
 * @see https://secure.php.net/manual/en/book.password.php
 */
trait Password
{
	/**
	 * Creates a password hash
	 * @param string $password The user's password.
	 * @param int    $algo     A password algorithm constant
	 * @param array  $options  An associative array containing options
	 * @return string
	 * @see https://php.net/manual/en/function.password-hash.php
	 */
	final protected function passwordHash(
		String $password,
		Int    $algo    = PASSWORD_DEFAULT,
		Array  $options = array()
	): String
	{
		return password_hash($password, $algo, $options);
	}

	/**
	 * Verifies that a password matches a hash
	 * @param string $password The user's password.
	 * @param string $hash     A hash created by password_hash()
	 * @return bool            TRUE if the password and hash match, or FALSE otherwise.
	 * @see https://php.net/manual/en/function.password-verify.php
	 */
	final protected function passwordVerify(String $password, String $hash = ''): Bool
	{
		return password_verify($password, $hash);
	}

	/**
	 * Returns information about the given hash
	 * @param string $hash A hash created by password_hash().
	 * @return array
	 * @see https://php.net/manual/en/function.password-get-info.php
	 */
	final protected function passwordGetInfo(String $hash): Array
	{
		return password_get_info($hash);
	}

	/**
	 * Checks if the given hash matches the given options
	 * @param string $hash    A hash created by password_hash()
	 * @param int    $algo    A password algorithm constant
	 * @param array  $options An associative array containing options
	 * @return bool
	 * @see https://php.net/manual/en/function.password-needs-rehash.php
	 */
	final protected function passwordNeedsRehash(
		String $hash,
		Int    $algo    = PASSWORD_DEFAULT,
		Array  $options = array()
	): Bool
	{
		return password_needs_rehash($hash, $algo, $options);
	}

}

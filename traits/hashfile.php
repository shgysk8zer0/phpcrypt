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
/**
 * @see https://secure.php.net/manual/en/function.hash-file.php
 */
trait HashFile
{
	/**
	 * Generates a SHA-1 digest from a file
	 * @param  String $fname File to be hashed
	 * @return String        The calculated file digest as lowercase hexits
	 */
	final public static function sha1File(String $fname): String
	{
		return hash_file('sha1', $fname);
	}

	/**
	 * Generates a SHA-256 digest from a file
	 * @param  String $fname File to be hashed
	 * @return String        The calculated file digest as lowercase hexits
	 */
	final public static function sha256File(String $fname): String
	{
		return hash_file('sha256', $fname);
	}

	/**
	 * Generates a SHA-384 digest from a file
	 * @param  String $fname File to be hashed
	 * @return String        The calculated file digest as lowercase hexits
	 */
	final public static function sha384File(String $fname): String
	{
		return hash_file('sha384', $fname);
	}

	/**
	 * Generates a SHA-512 digets from a file
	 * @param  String $fname File to be hashed
	 * @return String        The calculated file digest as lowercase hexits
	 */
	final public static function sha512File(String $fname): String
	{
		return hash_file('sha512', $fname);
	}

	/**
	 * Timing attack safe file comparison
	 * @param  String $fname  The file
	 * @param  String $hash   The hash to check against
	 * @return Bool           If the hash matches the file
	 * @see https://php.net/manual/en/function.hash-equals.php
	 */
	final public static function matchFile(String $fname, String $hash): Bool
	{
		switch(strlen($hash)) {
			case 40:
				$str = static::sha1File($fname);
				break;

			case 64:
				$str = static::sha256File($fname);
				break;

			case 96:
				$str = static::sha384File($fname);
				break;

			case 129:
				$str = static::sha512File($fname);
				break;

			default:
				trigger_error('Could not match with any supported hashing algorithm.');
				$str = '';
		}
		return hash_equals($str, $hash);
	}
}

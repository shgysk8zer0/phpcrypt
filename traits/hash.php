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
 * @see https://secure.php.net/manual/en/function.hash.php
 */
trait Hash
{
	/**
	 * Generates a SHA-1 digest
	 * @param  String $str Message to be hashed
	 * @return String      The calculated message digest as lowercase hexits
	 */
	final public static function sha1(String $str): String
	{
		return hash('sha1', $str);
	}

	/**
	 * Generates a SHA-256 digest
	 * @param  String $str Message to be hashed
	 * @return String      The calculated message digest as lowercase hexits
	 */
	final public static function sha256(String $str): String
	{
		return hash('sha256', $str);
	}

	/**
	 * Generates a SHA-384 digest
	 * @param  String $str Message to be hashed
	 * @return String      The calculated message digest as lowercase hexits
	 */
	final public static function sha384(String $str): String
	{
		return hash('sha384', $str);
	}

	/**
	 * Generates a SHA-512 digets
	 * @param  String $str Message to be hashed
	 * @return String      The calculated message digest as lowercase hexits
	 */
	final public static function sha512(String $str): String
	{
		return hash('sha512', $str);
	}

	/**
	 * Timing attack safe string comparison
	 * @param  String $str  The message
	 * @param  String $hash The hash to check against
	 * @return Bool         If the hash matches the message
	 * @see https://php.net/manual/en/function.hash-equals.php
	 */
	final public static function match(String $str, String $hash): Bool
	{
		switch(strlen($hash)) {
			case 40:
				$str = static::sha1($str);
				break;

			case 64:
				$str = static::sha256($str);
				break;

			case 96:
				$str = static::sha384($str);
				break;

			case 128:
				$str = static::sha512($str);
				break;

			default:
				trigger_error('Could not match with any supported hashing algorithm.');
				$str = '';
		}
		return hash_equals($str, $hash);
	}
}

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
namespace shgysk8zer0\PHPCrypt\Interfaces;

use \shgysk8zer0\PHPCrypt\Abstracts as Abstracts;

/**
 * Interface for all keys.
 * Not that public and private keys behave slightly differently. Namely,
 * private keys take more arguments, including passwords, when importing & exporting
 */
interface Key
{
	/**
	 * Import key from string
	 * @param  String $data "-----BEGIN PUBLIC|PRIVATE( [ENCRYPTED])? KEY-----...."
	 * @return self         Key
	 */
	public static function import(String $data);

	/**
	 * Import a key form a file
	 * @param  String        $filename /path/to/key.pem
	 * @return self          Imported Key
	 */
	public static function importFromFile(String $filename);

	/**
 	 * Encrypt $data using a key.
 	 * Can be decrypted by matching key
 	 * @param  String  $data    The data to encrypt using key
	 * @param  boolean $raw     Whether or not to use binary output
 	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
 	 * @return String           Data encrypted using the key
 	 */
	public function encrypt(String $data, Bool $raw = false, Int $padding): String;

	/**
 	 * Decrypt data using key
 	 * @param  String  $data    Data encrypted by matching key
	 * @param  boolean $raw     Whether or not to use binary output
 	 * @param  integer $padding Padding contant <https://php.net/manual/en/openssl.padding.php>
 	 * @return String           Data decrypted using the key
 	 */
	public function decrypt(String $data, Bool $raw = false, Int $padding): String;

	/**
	 * Export the contents of the key as a string
	 * @return String "-----BEGIN PUBLIC|PRIVATE( ENCRYPTED)? KEY-----...."
	 */
	public function export(): String;

	/**
	 * Export the key to file
	 * @param  String $filename /path/to/key.pem
	 * @return Bool             Whether or not it saved successfully
	 */
	public function exportToFile(String $filename): Bool;
}

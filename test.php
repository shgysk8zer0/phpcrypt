<?php
declare(strict_types=1);
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

const PASSWORD    = 'fooBar42';
const PUBLIC_KEY  = 'public.pem';
const PRIVATE_KEY = 'private.pem';
const MESSAGE     = 'Hello world!';
const ERROR_LOG   = 'errors.log';

if (PHP_SAPI !== 'cli') {
	http_response_code(503);
	exit();
} elseif (version_compare(\PHP_VERSION, '7.0.0', '<')) {
	echo 'PHP version 7 or greater is required.' . PHP_EOL;
	exit(1);
}

/**
 * Function to register in `set_error_handler`, throws an `\ErrorException`
 * @param  integeer $errno      Error level
 * @param  String   $errstr     Error message
 * @param  String   $errfile    File the error occured in
 * @param  integer  $errline    Line in $errfile
 * @param  array    $errcontext Variables defined in the scope of error
 * @return Bool                 True prevent default error handler
 */
function error_handler(
	Int    $errno,
	String $errstr,
	String $errfile    = null,
	Int    $errline    = null,
	Array  $errcontext = array()
) : Bool
{
	exception_handler(new \ErrorException($errstr, 0, $errno, $errfile, $errline));
	return true;
}

/**
 * Function to register in `set_exception_handler`. Logs and echoes exception, then exits
 * @param  Throwable $exc  The error or exception
 * @return void
 */
function exception_handler(\Throwable $exc)
{
	error_log($exc . PHP_EOL, 3, ERROR_LOG);
	echo $exc;
	exit(1);
}

/**
 * Recursively lint a directory
 * @param  String   $dir            Directory to lint
 * @param  Array    $exts           Array of extensions to lint in directory
 * @param  Array    $ignore_dirs    Ignore directories in this array
 * @param  Callable $error_callback Callback to call when linting fails
 * @return Bool                     Whether or not all files linted without errors
 * @see https://secure.php.net/manual/en/class.recursiveiteratoriterator.php
 */
function lint_dir(
	String   $dir            = __DIR__,
	Array    $exts           = ['php', 'phtml'],
	Array    $ignore_dirs    = ['.git', 'node_modules', 'vendor'],
	Callable $error_callback = null
): Bool
{
	$path = new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS);

	while ($path->valid()) {
		echo "Linting {$path->getPathName()}" . PHP_EOL;
		ob_start();
		if ($path->isFile() and in_array($path->getExtension(), $exts)) {
			$output = [];
			$msg = @exec(
				sprintf("php -l %s", escapeshellarg($path->getPathName())),
				$output,
				$return_var
			);

			if ($return_var !== 0) {
				if (isset($error_callback)) {
					$error_callback($msg);
					return false;
				} else {
					throw new \ParseError($msg);
				}
			}
		} elseif ($path->isDir() and ! in_array($path, $ignore_dirs)) {
			// So long as $dir is the first argument of the function, this will
			// always work, even if the name of the function changes.
			$args = array_slice(func_get_args(), 1);
			call_user_func(__FUNCTION__, $path->getPathName(), ...$args);
		}
		$path->next();
	}
	ob_get_clean();
	return true;
}

// Setup autoloading
set_include_path(dirname(__DIR__, 2) . PATH_SEPARATOR . __DIR__);
spl_autoload_register('spl_autoload');

// Set error and exception handlers
set_error_handler(__NAMESPACE__ . '\error_handler', E_ALL);
set_exception_handler(__NAMESPACE__ . '\exception_handler');

// Set asser options
assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_BAIL, 1);

assert(lint_dir(__DIR__), 'Linting PHP scripts failed');

$pair = KeyPair::generateKeyPair(PASSWORD);
$pair->public->exportToFile(PUBLIC_KEY);
$pair->private->exportToFile(PRIVATE_KEY, PASSWORD);

$keys = new KeyPair(PUBLIC_KEY, PRIVATE_KEY, PASSWORD);

$rsa_enc    = $keys->encrypt(MESSAGE);
$rsa_dec    = $keys->decrypt($rsa_enc);
$sig        = $keys->sign($rsa_enc);
$sig_valid  = $keys->verify($rsa_enc, $sig);
$hash       = Hash::sha384(MESSAGE);
$hash_match = Hash::match(MESSAGE, $hash);
$file_hash  = Hash::sha512File(__FILE__);
$file_match = Hash::matchFile(__FILE__, $file_hash);
$aes_enc    = AES::encrypt(MESSAGE, PASSWORD);
$aes_dec    = AES::decrypt($aes_enc, PASSWORD);

print_r([
	'keys'       => "$keys",
	'message'    => MESSAGE,
	'RSA enc'    => $rsa_enc,
	'AES enc'    => $aes_enc,
	'RSA match'  => $rsa_dec === MESSAGE,
	'AES match'  => $aes_dec === MESSAGE,
	'signature'  => $sig,
	'sig valid'  => $sig_valid,
	'hash'       => $hash,
	'hash match' => $hash_match,
	'file hash'  => $file_hash,
	'file match' => $file_match,
]);

assert($rsa_dec === MESSAGE, 'Decrypted RSA message matches MESSAGE.');
assert($aes_dec === MESSAGE, 'Decrypted AES message matches MESSAGE.');
assert($sig_valid,           'Signature is valid.');
assert($hash_match,          'Hash matches.');
assert($file_match,          'File hash matches.');
echo 'All tests passed successfully.';

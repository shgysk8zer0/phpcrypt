<?php
namespace shgysk8zer0\PHPCrypt;

const PASSWORD    = 'fooBar42';
const PUBLIC_KEY  = 'public.pem';
const PRIVATE_KEY = 'private.pem';
const MESSAGE     = 'Hello world!';
const ERROR_LOG   = 'errors.log';

if (! in_array(PHP_SAPI, ['cli', 'cli-server'])) {
	http_response_code(503);
	exit();
} elseif (version_compare(\PHP_VERSION, '7.0.0', '<')) {
	echo 'PHP version 7 or greater is required.' . PHP_EOL;
	exit(1);
}

set_include_path(dirname(__DIR__, 2) . PATH_SEPARATOR . __DIR__);
spl_autoload_register('spl_autoload');

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
	echo json_encode([
		'message' => $exc->getMessage(),
		'file'    => $exc->getFile(),
		'line'    => $exc->getLine(),
		'trace'   => $exc->getTrace(),
	], JSON_PRETTY_PRINT) . PHP_EOL;
	exit(1);
}

set_error_handler(__NAMESPACE__ . '\error_handler', E_ALL);
set_exception_handler(__NAMESPACE__ . '\exception_handler');

$pair = KeyPair::generateKeyPair(PASSWORD);
$pair->public->exportToFile(PUBLIC_KEY);
$pair->private->exportToFile(PRIVATE_KEY, PASSWORD);

$keys = new KeyPair(PUBLIC_KEY, PRIVATE_KEY, PASSWORD);

$encrypted  = $keys->encrypt(MESSAGE);
$decrypted  = $keys->decrypt($encrypted);
$sig        = $keys->sign($encrypted);
$valid      = $keys->verify($encrypted, $sig);
$hash       = Hash::sha384(MESSAGE);
$matches    = Hash::match(MESSAGE, $hash);
$file_hash  = Hash::sha512File(__FILE__);
$file_match = Hash::matchFile(__FILE__, $file_hash);


@header('Content-Type: application/json');
echo json_encode([
	'keys'       => "$keys",
	'message'    => MESSAGE,
	'encrypted'  => $encrypted,
	'decrypted'  => $decrypted,
	'match'      => MESSAGE === $decrypted,
	'signature'  => $sig,
	'valid'      => $valid,
	'hash'       => $hash,
	'hash match' => $matches,
	'file hash'  => $file_hash,
	'file match' => $file_match,
], JSON_PRETTY_PRINT);

if (!$decrypted === MESSAGE) {
	trigger_error('Decrypted message does not match original.');
} elseif (!$valid) {
	trigger_error('Signature not valid.');
} elseif (!$matches) {
	trigger_error('Hash does not match');
} elseif (!$file_match) {
	trigger_error(sprintf('Hash for %s did not match', __FILE__));
}

<?php
/**
 * @author Chris Zuber
 * @version 1.0.0
 * @package shgysk8zer0/PHPCrypt
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
 * Creates and verifies cryptographic/RSA signatures in forms
 *
 * Quite possibly the most secure/paranoid way to verify the authenticity of a
 * form submission.
 * Appends user IP address to form, so the form cannot be submitted elsewhere.
 * Appends form name to form, so signature cannot be used on other forms.
 * Appends expiration time to form, so they have limited re-use.
 * Appends signature to form, so none of the above may be changed.
 *
 * @uses <https://github.com/shgysk8zer0/phpcrypt/blob/master/traits/pkey.php>
 */
final class FormSign extends KeyPair
{
	use Traits\PKey;

	/**
	 * Array to store instances of class by config files
	 * @var Array
	 */
	private static $_form_instances = [];

	/**
	 * Static method to load from JSON config file
	 * @param  String $creds JSON file containing key paths and password
	 * @return self          New or existing instance of self
	 */
	public static function load(String $creds): self
	{
		// Check that it has an extension. If not, make it a ".json"
		$ext = pathinfo($creds, PATHINFO_EXTENSION);
		if (!$ext) {
			$creds .= '.json';
		}

		// Check if instance should exist in static array. If so, return it.
		// If not, create one, store it in the static array, then return that.
		if (! array_key_exists($creds, static::$_form_instances)) {
			$obj = json_decode(file_get_contents($creds, true));

			static::$_form_instances[$creds] = new self(
				$obj->publicKey,
				$obj->privateKey,
				$obj->password ?? null
			);
		}
		return static::$_form_instances[$creds];
	}

	/**
	 * Appends cryptographic signature, IP,  and timestamp to a `<form>`
	 * @param  DOMElement  $form      The form to add hidden inputs to
	 * @param  string      $expires   How long is the form valid?
	 * @param  string      $array_key Key in form data for input names
	 * @return DOMElement             The `<form>` with appended `<input>`s
	 */
	public function signForm(
		\DOMElement $form,
		String      $expires = '+2 hours',
		String      $arr_key = 'verification'
	): \DOMElement
	{
		// Check that this is a form and it has a name
		if ($form->tagName !== 'form') {
			trigger_error(sprintf('Expected of <form>, but got a <%s>'. $form->tagName));
			return $form;
		} elseif (!$form->hasAttribute('name') or $form->getAttribute('name') === '') {
			trigger_error('Forms require a name in order to be signed.');
			return $form;
		}

		$doc = $form->ownerDocument;
		$name = $form->getAttribute('name');

		// Create hidden inputs <input type="hidden" name="" value=""/>
		$ip = $form->appendChild($doc->createElement('input'));
		$ip->setAttribute('type', 'hidden');
		$ip->setAttribute('name', "{$name}[{$arr_key}][ip]");
		$ip->setAttribute('value', $_SERVER['REMOTE_ADDR']);

		$expire = $form->appendChild($doc->createElement('input'));
		$expire->setAttribute('type', 'hidden');
		$expire->setAttribute('name', "{$name}[{$arr_key}][expires]");
		$expire->setAttribute('value', strtotime($expires));

		$form_name = $form->appendChild($doc->createElement('input'));
		$form_name->setAttribute('type', 'hidden');
		$form_name->setAttribute('name', "{$name}[{$arr_key}][name]");
		$form_name->setAttribute('value', $name);

		// Create signature for these inputs' values. Base64 encode it.
		$signature = $this->sign(join('-', [
			$name,
			$ip->getAttribute('value'),
			$expire->getAttribute('value'),
		]));

		$sig = $form->appendChild($doc->createElement('input'));
		$sig->setAttribute('type', 'hidden');
		$sig->setAttribute('name', "{$name}[{$arr_key}][signature]");
		$sig->setAttribute('value', $signature);
		return $form;
	}

	/**
	 * Same as `signForm`, except works with HTML string instead
	 * @param  string  $form      The form to add hidden inputs to
	 * @param  string  $expires   How long is the form valid?
	 * @param  string  $array_key Key in form data for input names
	 * @return string             The `<form>` with appended `<input>`s
	 */
	public function signFormHTML(
		String $form,
		String $expires = '+2 hours',
		String $arr_key = 'verification'
	): String
	{
		// Create DOM and load $form into it.
		$doc = new \DOMDocument();
		$doc->loadHTML($form);
		$form_els = $doc->getElementsByTagName('form');
		if (!$form_els) {
			trigger_error('Attempting to sign <form> on HTML that does not contain a form.');
			return $form;
		} else {
			$html = '';

			// Iterate through any forms, signing each
			foreach ($form_els as $form_el) {
				$this->signForm($form_el, $expires, $arr_key);
				$html .= $doc->saveHTML($form_el);
			}
			return $html;
		}
	}

	/**
	 * Add a cryptographic signature & timestamp as `<input type=hidden..>`s
	 * @param  array   $req     Form data such as from `$_POST`
	 * @param  string  $arr_key Key in form data for input names
	 * @return Bool             Whether or not the data is valid and signature matches
	 */
	public function verifyFormSignature(Array $req, String $arr_key = 'verification'): Bool
	{
		// Verify that all necessary data exists
		if (!array_key_exists($arr_key, $req) or !is_array($req[$arr_key])) {
			trigger_error('No verification data found in form data.');
			return false;
		}

		$ver = new \ArrayObject($req[$arr_key], \ArrayObject::ARRAY_AS_PROPS);

		if (!isset($ver->name, $ver->ip, $ver->signature, $ver->expires)) {
			trigger_error('Invalid form signature formatting.');
			return false;
		}

		// Convert expires time into a timestamp / integer
		// Make sure that the current time is not greater than $expires
		$expires   = @intval($ver->expires);

		if (time() > $expires) {
			trigger_error('Form signature is expired.');
			return false;
		} elseif (
			// Check that IP is a valid IP and the source of the form submission
			!filter_var($ver->ip, FILTER_VALIDATE_IP)
			or $_SERVER['REMOTE_ADDR'] !== $ver->ip
		) {
			trigger_error('Form verification IP does not match user IP.');
			return false;
		}

		try {
			// If all is well so far, verify the signature
			if (!$this->verify(
				join('-', [
					$ver->name,
					$ver->ip,
					$ver->expires,
				]),
				$ver->signature
			)) {
				trigger_error('Form signature is invalid');
				return false;
			}
		} catch (\Throwable $e) {
			trigger_error($e->getMessage());
			return false;
		}

		return true;
	}
}

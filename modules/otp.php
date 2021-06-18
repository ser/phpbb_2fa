<?php

declare(strict_types=1);

namespace Base32;

/**
 * Base32 encoder and decoder.
 *
 * RFC 4648 compliant
 *
 * @see     http://www.ietf.org/rfc/rfc4648.txt
 * Some groundwork based on this class
 * https://github.com/NTICompass/PHP-Base32
 *
 * @author  Christian Riesen <chris.riesen@gmail.com>
 * @author  Sam Williams <sam@badcow.co>
 *
 * @see     http://christianriesen.com
 *
 * @license MIT License see LICENSE file
 */
class Base32
{
    /**
     * Alphabet for encoding and decoding base32.
     *
     * @var string
     */
    protected const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';

    protected const BASE32HEX_PATTERN = '/[^A-Z2-7]/';

    /**
     * Maps the Base32 character to its corresponding bit value.
     */
    protected const MAPPING = [
        '=' => 0b00000,
        'A' => 0b00000,
        'B' => 0b00001,
        'C' => 0b00010,
        'D' => 0b00011,
        'E' => 0b00100,
        'F' => 0b00101,
        'G' => 0b00110,
        'H' => 0b00111,
        'I' => 0b01000,
        'J' => 0b01001,
        'K' => 0b01010,
        'L' => 0b01011,
        'M' => 0b01100,
        'N' => 0b01101,
        'O' => 0b01110,
        'P' => 0b01111,
        'Q' => 0b10000,
        'R' => 0b10001,
        'S' => 0b10010,
        'T' => 0b10011,
        'U' => 0b10100,
        'V' => 0b10101,
        'W' => 0b10110,
        'X' => 0b10111,
        'Y' => 0b11000,
        'Z' => 0b11001,
        '2' => 0b11010,
        '3' => 0b11011,
        '4' => 0b11100,
        '5' => 0b11101,
        '6' => 0b11110,
        '7' => 0b11111,
    ];

    /**
     * Encodes into base32.
     *
     * @param string $string Clear text string
     *
     * @return string Base32 encoded string
     */
    public static function encode(string $string): string
    {
        // Empty string results in empty string
        if ('' === $string) {
            return '';
        }

        $encoded = '';

        //Set the initial values
        $n = $bitLen = $val = 0;
        $len = \strlen($string);

        //Pad the end of the string - this ensures that there are enough zeros
        $string .= \str_repeat(\chr(0), 4);

        //Explode string into integers
        $chars = (array) \unpack('C*', $string, 0);

        while ($n < $len || 0 !== $bitLen) {
            //If the bit length has fallen below 5, shift left 8 and add the next character.
            if ($bitLen < 5) {
                $val = $val << 8;
                $bitLen += 8;
                $n++;
                $val += $chars[$n];
            }
            $shift = $bitLen - 5;
            $encoded .= ($n - (int)($bitLen > 8) > $len && 0 == $val) ? '=' : static::ALPHABET[$val >> $shift];
            $val = $val & ((1 << $shift) - 1);
            $bitLen -= 5;
        }

        return $encoded;
    }

    /**
     * Decodes base32.
     *
     * @param string $base32String Base32 encoded string
     *
     * @return string Clear text string
     */
    public static function decode(string $base32String): string
    {
        // Only work in upper cases
        $base32String = \strtoupper($base32String);

        // Remove anything that is not base32 alphabet
        $base32String = \preg_replace(static::BASE32HEX_PATTERN, '', $base32String);

        // Empty string results in empty string
        if ('' === $base32String || null === $base32String) {
            return '';
        }

        $decoded = '';

        //Set the initial values
        $len = \strlen($base32String);
        $n = 0;
        $bitLen = 5;
        $val = static::MAPPING[$base32String[0]];

        while ($n < $len) {
            //If the bit length has fallen below 8, shift left 5 and add the next pentet.
            if ($bitLen < 8) {
                $val = $val << 5;
                $bitLen += 5;
                $n++;
                $pentet = $base32String[$n] ?? '=';

                //If the new pentet is padding, make this the last iteration.
                if ('=' === $pentet) {
                    $n = $len;
                }
                $val += static::MAPPING[$pentet];
                continue;
            }
            $shift = $bitLen - 8;

            $decoded .= \chr($val >> $shift);
            $val = $val & ((1 << $shift) - 1);
            $bitLen -= 8;
        }

        return $decoded;
    }
}
/**
 * OTPAuthenticate
 * @package OTPAuthenticate
 * @copyright (c) Marc Alexander <admin@m-a-styles.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OTPAuthenticate;

use Base32\Base32;

class OTPAuthenticate
{
	/** int verification code modulus */
	const VERIFICATION_CODE_MODULUS = 1e6;

	/** int Secret length */
	protected $secret_length;

	/** int code length */
	protected $code_length;

	/** \Base32\Base32 */
	protected $base32;

	/**
	 * Constructor for OTPAuthenticate
	 *
	 * @param int $code_length Code length
	 * @param int $secret_length Secret length
	 */
	public function __construct($code_length = 6, $secret_length = 10)
	{
		$this->code_length = $code_length;
		$this->secret_length = $secret_length;

		$this->base32 = new Base32();
	}

	/**
	 * Generates code based on timestamp and secret
	 *
	 * @param string $secret Secret shared with user
	 * @param int $counter Counter for code generation
	 * @param string $algorithm Algorithm to use for HMAC hash.
	 *			Defaults to sha512. The following hash types are allowed:
	 *				TOTP: sha1, sha256, sha512
	 *				HOTP: sha1
	 *
	 * @return string Generated OTP code
	 */
	public function generateCode($secret, $counter, $algorithm = 'sha512')
	{
		$key = $this->base32->decode($secret);

		if (empty($counter))
		{
			return '';
		}

		$hash = hash_hmac($algorithm, $this->getBinaryCounter($counter), $key, true);

		return str_pad(strval($this->truncate($hash)), $this->code_length, '0', STR_PAD_LEFT);
	}

	/**
	 * Check if supplied TOTP code is valid
	 *
	 * @param string $secret Secret to use for comparison
	 * @param int $code Supplied TOTP code
	 * @param string $hash_type Hash type
	 *
	 * @return bool True if code is valid, false if not
	 */
	public function checkTOTP($secret, $code, $hash_type = 'sha512')
	{
		$time = $this->getTimestampCounter(time());

		for ($i = -1; $i <= 1; $i++)
		{
			if (hash_equals($code, $this->generateCode($secret, $time + $i, $hash_type)) === true)
			{
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if supplied HOTP code is valid
	 *
	 * @param string $secret Secret to use for comparison
	 * @param int $counter Current counter
	 * @param int $code Supplied HOTP code
	 * @param string $hash_type Hash type
	 *
	 * @return bool True if code is valid, false if not
	 */
	public function checkHOTP($secret, $counter, $code, $hash_type = 'sha512')
	{
		return hash_equals($code, $this->generateCode($secret, $counter, $hash_type));
	}

	/**
	 * Truncate HMAC hash to binary for generating a TOTP code
	 *
	 * @param string $hash HMAC hash
	 *
	 * @return int Truncated binary hash
	 */
	protected function truncate($hash)
	{
		$truncated_hash = 0;
		$offset = ord(substr($hash, -1)) & 0xF;

		// Truncate hash using supplied sha1 hash
		for ($i = 0; $i < 4; ++$i)
		{
			$truncated_hash <<= 8;
			$truncated_hash  |= ord($hash[$offset + $i]);
		}

		// Truncate to a smaller number of digits.
		$truncated_hash &= 0x7FFFFFFF;
		$truncated_hash %= self::VERIFICATION_CODE_MODULUS;

		return $truncated_hash;
	}

	/**
	 * Get binary version of time counter
	 *
	 * @param int $counter Timestamp or counter
	 *
	 * @return string Binary time counter
	 */
	protected function getBinaryCounter($counter)
	{
		return pack('N*', 0) . pack('N*', $counter);
	}

	/**
	 * Get counter from timestamp
	 *
	 * @param int $time Timestamp
	 *
	 * @return int Counter
	 */
	public function getTimestampCounter($time)
	{
		return floor($time / 30);
	}

	/**
	 * Generate secret with specified length
	 *
	 * @param int $length
	 *
	 * @return string
	 */
	public function generateSecret($length = 10)
	{
		$strong_secret = false;

		// Try to get $crypto_strong to evaluate to true. Give it 5 tries.
		for ($i = 0; $i < 5; $i++)
		{
			$secret = openssl_random_pseudo_bytes($length, $strong_secret);

			if ($strong_secret === true)
			{
				return $this->base32->encode($secret);
			}
		}

		return '';
	}
}

/**
 * OTPHelper
 * @package OTPAuthenticate
 * @copyright (c) Marc Alexander <admin@m-a-styles.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OTPAuthenticate;

class OTPHelper
{
	/** @var array Allowed types of OTP */
	protected $allowedType = array(
		'hotp',
		'totp',
	);

	/** @var array Allowed algorithms */
	protected $allowedAlgorithm = array(
		'sha1',
		'sha256',
		'sha512',
	);

	/** @var string Label string for URI */
	protected $label;

	/** @var string Issuer string for URI */
	protected $issuer;

	/** @var string Additional parameters for URI */
	protected $parameters = '';

	/**
	 * Generate OTP key URI
	 *
	 * @param string $type OTP type
	 * @param string $secret Base32 encoded secret
	 * @param string $account Account name
	 * @param string $issuer Issuer name (optional)
	 * @param int $counter Counter for HOTP (optional)
	 * @param string $algorithm Algorithm name (optional)
	 * @param string $digits Number of digits for code (optional)
	 * @param string $period Period for TOTP codes (optional)
	 *
	 * @return string OTP key URI
	 */
	public function generateKeyURI($type, $secret, $account, $issuer = '', $counter = 0, $algorithm = '', $digits = '', $period = '')
	{
		// Check if type is supported
		$this->validateType($type);
		$this->validateAlgorithm($algorithm);

		// Format label string
		$this->formatLabel($issuer, 'issuer');
		$this->formatLabel($account, 'account');

		// Set additional parameters
		$this->setCounter($type, $counter);
		$this->setParameter($algorithm, 'algorithm');
		$this->setParameter($digits, 'digits');
		$this->setParameter($period, 'period');

		return 'otpauth://' . $type . '/' . $this->label . '?secret=' . $secret . $this->issuer . $this->parameters;
	}

	/**
	 * Check if OTP type is supported
	 *
	 * @param string $type OTP type
	 *
	 * @throws \InvalidArgumentException When type is not supported
	 */
	protected function validateType($type)
	{
		if (empty($type) || !in_array($type, $this->allowedType))
		{
			throw new \InvalidArgumentException("The OTP type $type is not supported");
		}
	}

	/**
	 * Check if algorithm is supported
	 *
	 * @param string $algorithm Algorithm to use
	 *
	 * @throws \InvalidArgumentException When algorithm is not supported
	 */
	protected function validateAlgorithm($algorithm)
	{
		if (!empty($algorithm) && !in_array($algorithm, $this->allowedAlgorithm))
		{
			throw new \InvalidArgumentException("The algorithm $algorithm is not supported");
		}
	}

	/**
	 * Format label string according to expected urlencoded standards.
	 *
	 * @param string $string The label string
	 * @param string $part Part of label
	 */
	protected function formatLabel($string, $part)
	{
		$string = trim($string);

		if ($part === 'account')
		{
			$this->setAccount($string);
		}
		else if ($part === 'issuer')
		{
			$this->setIssuer($string);
		}
	}

	/**
	 * Format and and set account name
	 *
	 * @param string $account Account name
	 *
	 * @throws \InvalidArgumentException When given account name is an empty string
	 */
	protected function setAccount($account)
	{
		if (empty($account))
		{
			throw new \InvalidArgumentException("Label can't contain empty strings");
		}

		$this->label .= str_replace('%40', '@', rawurlencode($account));
	}

	/**
	 * Format and set issuer
	 *
	 * @param string $issuer Issuer name
	 */
	protected function setIssuer($issuer)
	{
		if (!empty($issuer))
		{
			$this->label = rawurlencode($issuer) . ':';
			$this->issuer = '&issuer=' . rawurlencode($issuer);
		}
	}

	/**
	 * Set parameter if it is defined
	 *
	 * @param string $data Data to set
	 * @param string $name Name of data
	 */
	protected function setParameter($data, $name)
	{
		if (!empty($data))
		{
			$this->parameters .= "&$name=" . rawurlencode($data);
		}
	}

	/**
	 * Set counter value if hotp is being used
	 *
	 * @param string $type Type of OTP auth, either HOTP or TOTP
	 * @param int $counter Counter value
	 *
	 * @throws \InvalidArgumentException If counter is empty while using HOTP
	 */
	protected function setCounter($type, $counter)
	{
		if ($type === 'hotp')
		{
			if ($counter !== 0 && empty($counter))
			{
				throw new \InvalidArgumentException("Counter can't be empty if HOTP is being used");
			}

			$this->parameters .= "&counter=$counter";
		}
	}
}
/**
 *
 * 2FA extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2015 Paul Sohier
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace paul999\tfa\modules;

use OTPAuthenticate\OTPAuthenticate;
use OTPAuthenticate\OTPHelper;
use phpbb\db\driver\driver_interface;
use phpbb\exception\http_exception;
use phpbb\request\request_interface;
use phpbb\template\template;
use phpbb\user;

class otp extends abstract_module
{
	/**
	 * @var OTPHelper
	 */
	private $otp_helper;

	/**
	 * @var OTPAuthenticate
	 */
	private $otp;

	/**
	 * @var request_interface
	 */
	private $request;

	/**
	 * @var string
	 */
	private $otp_registration_table;

	/**
	 * OTP constructor.
	 *
	 * @param driver_interface $db
	 * @param user $user
	 * @param request_interface $request
	 * @param template $template
	 * @param string                            $otp_registration_table
	 */
	public function __construct(driver_interface $db, user $user, request_interface $request, template $template, $otp_registration_table)
	{
		$this->otp_helper = new OTPHelper();
		$this->otp = new OTPAuthenticate();
		$this->db = $db;
		$this->user = $user;
		$this->request = $request;
		$this->template = $template;
		$this->otp_registration_table = $otp_registration_table;
	}

	/**
	 * Get a language key for this specific module.
	 * @return string
	 */
	public function get_translatable_name()
	{
		return 'TFA_OTP';
	}

	/**
	 * Return the name of the current module
	 * This is for internal use only
	 * @return string
	 */
	public function get_name()
	{
		return 'otp';
	}

	/**
	 * Return if this module is enabled by the admin
	 * (And all server requirements are met).
	 *
	 * Do not return false in case a specific user disabled this module,
	 * OR if the user is unable to use this specific module,
	 * OR if a browser specific item is missing/incorrect.
	 * @return boolean
	 */
	public function is_enabled()
	{
		return true;
	}

	/**
	 * Check if the current user is able to use this module.
	 *
	 * This means that the user enabled it in the UCP,
	 * And has it setup up correctly.
	 * This method will be called during login, not during registration/
	 *
	 * @param int $user_id
	 *
	 * @return bool
	 */
	public function is_usable($user_id)
	{
		return $this->check_table_for_user($this->otp_registration_table, $user_id);
	}

	/**
	 * Check if the user can potentially use this.
	 * This method is called at registration page.
	 *
	 * You can, for example, check if the current browser is suitable.
	 *
	 * @param int|boolean $user_id Use false to ignore user
	 *
	 * @return bool
	 */
	public function is_potentially_usable($user_id = false)
	{
		return true;
	}

	/**
	 * Check if the user has any key registered with this module.
	 * There should be no check done if the key is usable, it should
	 * only return if a key is registered.
	 *
	 * @param $user_id
	 * @return bool
	 */
	public function key_registered($user_id)
	{
		return $this->check_table_for_user($this->otp_registration_table, $user_id);
	}

	/**
	 * Get the priority for this module.
	 * A lower priority means more chance it gets selected as default option
	 *
	 * There can be only one module with a specific priority!
	 * If there is already a module registered with this priority,
	 * a Exception might be thrown
	 *
	 * @return int
	 */
	public function get_priority()
	{
		return 15;
	}

	/**
	 * Start of the login procedure.
	 *
	 * @param int $user_id
	 *
	 * @return array
	 */
	public function login_start($user_id)
	{
		return array(
			'S_TFA_INCLUDE_HTML'	=> '@paul999_tfa/tfa_otp_authenticate.html',
		);
	}

	/**
	 * Actual login procedure
	 *
	 * @param int $user_id
	 *
	 * @return bool
	 */
	public function login($user_id)
	{
		$key = $this->request->variable('authenticate', '');

		if (empty($key))
		{
			throw new http_exception(400, 'TFA_NO_KEY_PROVIDED');
		}

		foreach ($this->getRegistrations($user_id) as $registration)
		{
			if ($this->otp->checkTOTP($registration['secret'], $key, 'sha1'))
			{
				// We found a valid key.
				$sql_ary = array(
					'last_used' => time(),
				);
				$sql = 'UPDATE ' . $this->otp_registration_table . ' 
					SET ' . $this->db->sql_build_array('UPDATE', $sql_ary) . ' 
					WHERE 
						registration_id = ' . (int) $registration['registration_id'];
				$this->db->sql_query($sql);
				return true;
			}
		}
		return false;
	}

	/**
	 * If this module can add new keys (Or other things)
	 *
	 * @return boolean
	 */
	public function can_register()
	{
		return true;
	}

	/**
	 * Start with the registration of a new security key.
	 * This page should return a name of a template, and
	 * it should assign the required variables for this template.
	 *
	 * @return string
	 */
	public function register_start()
	{
		$secret = $this->otp->generateSecret();
		$QR = $this->otp_helper->generateKeyURI('totp', $secret, $this->user->data['username'], generate_board_url(), 0, 'sha1');
		$this->template->assign_vars(array(
			'TFA_QR_CODE'				=> 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . $QR,
			'TFA_SECRET'				=> $secret,
			'L_TFA_ADD_OTP_KEY_EXPLAIN'	=> $this->user->lang('TFA_ADD_OTP_KEY_EXPLAIN', $secret),
			'S_HIDDEN_FIELDS_MODULE'	=> build_hidden_fields(array(
				'secret'	=> $secret,
			)),
		));

		return 'tfa_otp_ucp_new';
	}

	/**
	 * Do the actual registration of a new security key.
	 *
	 * @throws http_exception
	 */
	public function register()
	{
		$secret = $this->request->variable('secret', '');
		$otp	= $this->request->variable('register', '');

		if (!$this->otp->checkTOTP($secret, $otp, 'sha1'))
		{
			throw new http_exception(400, 'TFA_OTP_INVALID_KEY');
		}

		$sql_ary = array(
			'user_id' 		=> $this->user->data['user_id'],
			'secret'		=> $secret,
			'registered' 	=> time(),
			'last_used' 	=> time(),
		);

		$sql = 'INSERT INTO ' . $this->otp_registration_table . ' ' . $this->db->sql_build_array('INSERT', $sql_ary);
		$this->db->sql_query($sql);
	}

	/**
	 * This method is called to show the UCP page.
	 * You can assign template variables to the template, or do anything else here.
	 */
	public function show_ucp()
	{
		$this->show_ucp_complete($this->otp_registration_table);
	}

	/**
	 * Delete a specific row from the UCP.
	 * The data is based on the data provided in show_ucp.
	 *
	 * @param int $key
	 *
	 * @return void
	 */
	public function delete($key)
	{
		$sql = 'DELETE FROM ' . $this->otp_registration_table . '
			WHERE user_id = ' . (int) $this->user->data['user_id'] . '
			AND registration_id =' . (int) $key;

		$this->db->sql_query($sql);
	}

	/**
	 * Select all registration objects from the database
	 * @param integer $user_id
	 * @return array
	 */
	private function getRegistrations($user_id)
	{
		$sql = 'SELECT * FROM ' . $this->otp_registration_table . ' WHERE user_id = ' . (int) $user_id;
		$result = $this->db->sql_query($sql);
		$rows = $this->db->sql_fetchrowset($result);

		$this->db->sql_freeresult($result);
		return $rows;
	}
}

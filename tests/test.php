<?php

include('SecureHeaders.php');

class Test extends PHPUnit_Framework_TestCase
{
	private $assertions = array(
		'Contains',
		'NotContains',
		'Equals',
		'Regexp'
	);

	function data_safe_mode()
	{
		return array(
			[
				'test' => 
					function(&$headers){
						$headers->header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
					},
				'assertions' => [
					'Contains' => 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
				]
			],
			[
				'test' => 
					function(&$headers){
						$headers->safe_mode();
						$headers->header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
					},
				'assertions' => [
					'NotContains' => 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
					'Contains' => 'Strict-Transport-Security: max-age=86400'
				]
			],
			[
				'test' => 
					function(&$headers){
						$headers->safe_mode();
						$headers->header('Public-Key-Pins', 'max-age=31536000; pin-sha256="abcd"; includeSubDomains');
					},
				'assertions' => [
					'NotContains' => 'max-age=31536000; pin-sha256="abcd"; includeSubDomains',
					'Contains' => 'Public-Key-Pins: max-age=10; pin-sha256="abcd"'
				]
			]
		);
	}

	/**
     * @dataProvider data_safe_mode
	 * @param $test
	 * @param $assertions
     */
	public function test_safe_mode($test, $assertions)
	{
		$headers = new SecureHeaders;
		$headers->headers_as_string(true);
		$test($headers);

		$headers_string = $headers->get_headers_as_string();

		foreach ($this->assertions as $assertion)
		{
			if (isset($assertions[$assertion]))
			{
				$this->{'assert'.$assertion}($assertions[$assertion], $headers_string);
			}
		}
  	}
}   
?>
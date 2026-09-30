<?php
class Test_Detector extends WP_UnitTestCase {
	public function tear_down(): void { unset( $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR'] ); parent::tear_down(); }

	public function test_remote_addr_used_by_default() {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		$this->assertSame( '203.0.113.9', Counterprompt_Detector::client_ip() );
	}
	public function test_spoofed_xff_ignored_from_untrusted_source() {
		update_option( 'counterprompt_options', [ 'proxy_header' => 'X-Forwarded-For', 'proxy_cidrs' => [ '10.0.0.0/8' ] ] );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';       // not in trusted CIDR
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7';
		$this->assertSame( '203.0.113.9', Counterprompt_Detector::client_ip() );
	}
	public function test_xff_honored_from_trusted_source() {
		update_option( 'counterprompt_options', [ 'proxy_header' => 'X-Forwarded-For', 'proxy_cidrs' => [ '10.0.0.0/8' ] ] );
		$_SERVER['REMOTE_ADDR'] = '10.1.2.3';          // trusted proxy
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7, 10.1.2.3';
		$this->assertSame( '198.51.100.7', Counterprompt_Detector::client_ip() );
	}
	public function test_ipv6_hash_and_trunc() {
		$this->assertSame( '2001:db8:abcd::', Counterprompt_Detector::ip_trunc( '2001:db8:abcd:1234::1' ) );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', Counterprompt_Detector::ip_hash( '2001:db8::1' ) );
	}
	public function test_ipv4_trunc_zeroes_last_octet() {
		$this->assertSame( '203.0.113.0', Counterprompt_Detector::ip_trunc( '203.0.113.9' ) );
	}
	public function test_flag_roundtrip() {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		Counterprompt_Detector::flag( '203.0.113.9' );
		$this->assertTrue( Counterprompt_Detector::is_flagged( '203.0.113.9' ) );
		$this->assertFalse( Counterprompt_Detector::is_flagged( '198.51.100.1' ) );
	}
	public function test_allowlisted_ip_is_exempt_and_not_flagged() {
		update_option( 'counterprompt_options', [ 'allowlist' => [ '203.0.113.0/24' ] ] );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		Counterprompt_Detector::flag( '203.0.113.9' );
		$this->assertTrue( Counterprompt_Detector::is_exempt() );
		$this->assertFalse( Counterprompt_Detector::is_flagged( '203.0.113.9' ) );
	}
	public function test_editor_is_exempt() {
		$uid = self::factory()->user->create( [ 'role' => 'editor' ] );
		wp_set_current_user( $uid );
		$this->assertTrue( Counterprompt_Detector::is_exempt() );
	}
	public function test_ipv6_cidr_match() {
		$this->assertTrue( Counterprompt_Detector::ip_in_cidrs( '2001:db8::5', [ '2001:db8::/32' ] ) );
		$this->assertFalse( Counterprompt_Detector::ip_in_cidrs( '2001:dead::5', [ '2001:db8::/32' ] ) );
	}
}

<?php
class Test_Settings extends WP_UnitTestCase {
	public function test_defaults_present() {
		$d = Counterprompt_Settings::defaults();
		$this->assertSame( 'divert', $d['strategy'] );
		$this->assertSame( 0.7, $d['nd_probability'] );
		$this->assertTrue( $d['enabled'] );
	}
	public function test_get_returns_default_when_unset() {
		delete_option( 'counterprompt_options' );
		$prop = new ReflectionProperty( Counterprompt_Settings::class, 'cache' );
		$prop->setAccessible( true );
		$prop->setValue( Counterprompt_Settings::instance(), null );
		$this->assertSame( 0.7, Counterprompt_Settings::instance()->get( 'nd_probability' ) );
	}
	public function test_sanitize_clamps_probability() {
		$out = Counterprompt_Settings::instance()->sanitize( [ 'nd_probability' => '5' ] );
		$this->assertSame( 1.0, $out['nd_probability'] );
		$out = Counterprompt_Settings::instance()->sanitize( [ 'nd_probability' => '-1' ] );
		$this->assertSame( 0.0, $out['nd_probability'] );
	}
	public function test_sanitize_rejects_bad_paths() {
		$out = Counterprompt_Settings::instance()->sanitize( [ 'trap_paths' => "no-leading-slash\n/good" ] );
		$this->assertSame( [ '/good' ], $out['trap_paths'] );
	}
	public function test_sanitize_validates_cidrs() {
		$out = Counterprompt_Settings::instance()->sanitize( [ 'allowlist' => "10.0.0.0/8\nnonsense\n2001:db8::/32" ] );
		$this->assertSame( [ '10.0.0.0/8', '2001:db8::/32' ], $out['allowlist'] );
	}
	public function test_strategy_falls_back_to_divert() {
		$out = Counterprompt_Settings::instance()->sanitize( [ 'strategy' => 'bogus' ] );
		$this->assertSame( 'divert', $out['strategy'] );
	}
	public function test_sanitize_strips_notice_markup() {
		$out = Counterprompt_Settings::instance()->sanitize( [ 'notice_divert' => 'a--b</body>' ] );
		$this->assertFalse( strpos( $out['notice_divert'], '--' ) );
		$this->assertFalse( stripos( $out['notice_divert'], '</body' ) );
		$this->assertFalse( stripos( $out['notice_divert'], '<body' ) );
		$out = Counterprompt_Settings::instance()->sanitize( [ 'notice_divert' => 'x</<bodybody>y' ] );
		$this->assertFalse( stripos( $out['notice_divert'], '</body' ) );
		$this->assertFalse( stripos( $out['notice_divert'], '<body' ) );
	}
	public function test_sanitize_tolerates_absent_keys() {
		$out = Counterprompt_Settings::instance()->sanitize( [] );
		$this->assertSame( '', $out['proxy_header'] );
		$this->assertSame( [], $out['trap_paths'] );
	}
}

<?php
class Test_Leaks extends WP_UnitTestCase {
	public function set_up(): void {
		parent::set_up();
		update_option( 'counterprompt_options', [ 'nd_probability' => 1.0 ] );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
	}
	public function test_roll_respects_probability_bounds() {
		update_option( 'counterprompt_options', [ 'nd_probability' => 1.0 ] );
		$this->assertTrue( Counterprompt_Leaks::roll() );
		update_option( 'counterprompt_options', [ 'nd_probability' => 0.0 ] );
		$this->assertFalse( Counterprompt_Leaks::roll() );
	}
	public function test_author_enum_suppressed_when_flagged() {
		Counterprompt_Detector::flag( '203.0.113.9' );
		$this->assertTrue( Counterprompt_Leaks::should_suppress_author() );
	}
	public function test_author_enum_not_suppressed_when_unflagged() {
		$this->assertFalse( Counterprompt_Leaks::should_suppress_author() );
	}
	public function test_enum_is_trap_flags_unflagged_client() {
		update_option( 'counterprompt_options', [ 'nd_probability' => 1.0, 'enum_is_trap' => true ] );
		Counterprompt_Leaks::maybe_flag_on_enum();
		$this->assertTrue( Counterprompt_Detector::is_flagged( '203.0.113.9' ) );
	}
	public function test_fingerprint_path_detected() {
		$this->assertTrue( Counterprompt_Leaks::is_fingerprint_path( '/readme.html' ) );
		$this->assertTrue( Counterprompt_Leaks::is_fingerprint_path( '/wp-content/plugins/foo/readme.txt' ) );
		$this->assertFalse( Counterprompt_Leaks::is_fingerprint_path( '/about' ) );
	}
}

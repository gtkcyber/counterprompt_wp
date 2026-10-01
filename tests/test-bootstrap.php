<?php
class Test_Bootstrap extends WP_UnitTestCase {
	public function test_constants_defined() {
		$this->assertTrue( defined( 'COUNTERPROMPT_VERSION' ) );
		$this->assertTrue( defined( 'COUNTERPROMPT_DIR' ) );
		$this->assertStringEndsWith( '/', COUNTERPROMPT_DIR );
	}
	public function test_settings_class_loaded() {
		$this->assertTrue( class_exists( 'Counterprompt_Settings' ) );
	}
}

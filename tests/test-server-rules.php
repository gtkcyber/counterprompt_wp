<?php
class Test_Server_Rules extends WP_UnitTestCase {
	public function test_bait_paths_include_env_and_git() {
		$b = Counterprompt_Server_Rules::bait_paths();
		$this->assertContains( '/.env', $b );
		$this->assertContains( '/.git/config', $b );
	}
	public function test_htaccess_lines_rewrite_to_query_var() {
		$lines = implode( "\n", Counterprompt_Server_Rules::htaccess_lines() );
		$this->assertStringContainsString( 'counterprompt_trap', $lines );
		$this->assertStringContainsString( 'RewriteRule', $lines );
		$this->assertStringContainsString( 'RewriteRule ^\.env$', $lines );
	}
	public function test_nginx_snippet_mentions_location() {
		$this->assertStringContainsString( 'location', Counterprompt_Server_Rules::nginx_snippet() );
	}
	public function test_query_var_path_is_treated_as_trap() {
		$this->assertContains( '/.env', Counterprompt_Server_Rules::bait_paths() );
		$this->assertSame( '/.env', Counterprompt_Server_Rules::bait_path_from_request( '/.env' ) );
		$this->assertSame( '/.env', Counterprompt_Server_Rules::bait_path_from_request( '.env' ) );
	}
	public function test_arbitrary_query_values_are_ignored() {
		foreach ( [ '/', '/wp-admin', '/.env/../x', '', [ 'a' ] ] as $v ) {
			$this->assertSame( '', Counterprompt_Server_Rules::bait_path_from_request( $v ) );
		}
	}
	public function set_up(): void {
		parent::set_up();
		if ( ! has_filter( 'counterprompt_trap_paths' ) ) {
			Counterprompt_Server_Rules::boot();
		}
	}
	public function test_bait_paths_are_registered_as_traps() {
		$this->assertTrue( Counterprompt_Traps::is_trap( '/.env' ) );
		$this->assertTrue( Counterprompt_Traps::is_trap( '/.git/config' ) );
		$this->assertTrue( Counterprompt_Traps::is_trap( '/.aws/credentials' ) );
	}
	public function test_bait_paths_not_in_robots() {
		$this->assertStringNotContainsString( '.git/config', Counterprompt_Notices::robots( '' ) );
	}
	public function test_htaccess_write_remove_roundtrip() {
		$file = ABSPATH . '.htaccess';
		if ( file_exists( $file ) || ! is_writable( ABSPATH ) ) {
			$this->markTestSkipped( 'Will not touch an existing .htaccess / ABSPATH not writable.' );
		}
		try {
			$this->assertTrue( Counterprompt_Server_Rules::write() );
			$c = file_get_contents( $file );
			$this->assertStringContainsString( '# BEGIN Counterprompt', $c );
			$this->assertStringContainsString( 'RewriteRule', $c );
			$this->assertTrue( Counterprompt_Server_Rules::remove() );
			$this->assertStringNotContainsString( 'RewriteRule', (string) file_get_contents( $file ) );
		} finally {
			@unlink( $file );
		}
	}
	public function test_remove_safe_when_htaccess_absent() {
		if ( file_exists( ABSPATH . '.htaccess' ) ) {
			$this->markTestSkipped( 'existing .htaccess' );
		}
		$this->assertTrue( Counterprompt_Server_Rules::remove() );
	}
	public function test_toggle_only_acts_on_transition() {
		set_transient( 'cp_rules_write_failed', 'x' );
		Counterprompt_Server_Rules::on_update( [ 'server_rules_apache' => false ], [ 'server_rules_apache' => false ] );
		$this->assertSame( 'x', get_transient( 'cp_rules_write_failed' ) ); // untouched: no transition.
		Counterprompt_Server_Rules::on_update( [ 'server_rules_apache' => true ], [ 'server_rules_apache' => false ] );
		$this->assertFalse( get_transient( 'cp_rules_write_failed' ) ); // remove() path ran.
		$existed = file_exists( ABSPATH . '.htaccess' );
		Counterprompt_Server_Rules::on_update( [], [ 'server_rules_apache' => true ] );
		$this->assertContains( get_transient( 'cp_rules_write_failed' ), [ '0', '1' ] ); // write() path ran.
		Counterprompt_Server_Rules::remove();
		if ( ! $existed && file_exists( ABSPATH . '.htaccess' ) ) {
			unlink( ABSPATH . '.htaccess' );
		}
	}
	public function test_toggle_hooked_to_option_update() {
		Counterprompt_Server_Rules::register_toggle();
		$this->assertNotFalse( has_action( 'update_option_counterprompt_options', [ 'Counterprompt_Server_Rules', 'on_update' ] ) );
	}
	public function test_selftest_token_validation() {
		$this->assertFalse( Counterprompt_Server_Rules::selftest_token_valid( '1' ) );
		set_transient( 'cp_selftest_token', 'abc123', 60 );
		$this->assertTrue( Counterprompt_Server_Rules::selftest_token_valid( 'abc123' ) );
		$this->assertFalse( Counterprompt_Server_Rules::selftest_token_valid( 'nope' ) );
		delete_transient( 'cp_selftest_token' );
	}
}

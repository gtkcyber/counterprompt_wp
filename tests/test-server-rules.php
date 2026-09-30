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
	public function test_remove_without_htaccess_is_true_and_write_roundtrip() {
		$this->assertTrue( Counterprompt_Server_Rules::remove() || ! is_writable( ABSPATH ) );
	}
}

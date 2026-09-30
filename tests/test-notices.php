<?php
class Test_Notices extends WP_UnitTestCase {
	public function test_build_divert_has_attribution_and_divert_only() {
		update_option( 'counterprompt_options', [ 'strategy' => 'divert' ] );
		$sources = array_column( Counterprompt_Notices::build( 'rest' ), 'source' );
		$this->assertContains( 'attribution', $sources );
		$this->assertContains( 'divert', $sources );
		$this->assertNotContains( 'stop', $sources );
	}
	public function test_build_stop_swaps_divert_for_stop() {
		update_option( 'counterprompt_options', [ 'strategy' => 'stop' ] );
		$sources = array_column( Counterprompt_Notices::build( 'rest' ), 'source' );
		$this->assertContains( 'stop', $sources );
		$this->assertNotContains( 'divert', $sources );
	}
	public function test_footer_markup_has_hidden_link_and_comment() {
		update_option( 'counterprompt_options', [ 'trap_paths' => [ '/db-backup/' ] ] );
		$m = Counterprompt_Notices::footer_markup();
		$this->assertStringContainsString( 'display:none', $m );
		$this->assertStringContainsString( '/db-backup/', $m );
		$this->assertStringContainsString( '<!--', $m );
	}
	public function test_footer_markup_never_leaks_double_dash_into_comment() {
		update_option( 'counterprompt_options', [ 'notice_attribution' => 'bad--dashes </body> here' ] );
		$m = Counterprompt_Notices::footer_markup();
		// sanitize stripped -- and body tags at save; but build defensively too.
		$this->assertStringNotContainsString( '--dashes', $m );
		$this->assertStringNotContainsString( '</body>', $m );
	}
	public function test_robots_appends_disallow() {
		update_option( 'counterprompt_options', [ 'trap_paths' => [ '/db-backup/', '/.env.bak' ] ] );
		$out = Counterprompt_Notices::robots( "User-agent: *\nDisallow:\n" );
		$this->assertStringContainsString( 'Disallow: /db-backup/', $out );
		$this->assertStringContainsString( 'Disallow: /.env.bak', $out );
	}
	public function test_filter_can_add_notices() {
		add_filter( 'counterprompt_notices', fn( $n, $ctx ) => array_merge( $n, [ [ 'source' => 'x', 'text' => 'y' ] ] ), 10, 2 );
		$this->assertContains( 'x', array_column( Counterprompt_Notices::build( 'html' ), 'source' ) );
	}
	public function test_footer_markup_defeats_nested_tag_bypass() {
		update_option( 'counterprompt_options', [ 'notice_attribution' => 'a </bo</body>dy> b <<body>body x - -->- y ---> z' ] );
		$m = Counterprompt_Notices::footer_markup();
		$this->assertStringNotContainsString( '</body>', $m );
		$this->assertStringNotContainsString( '<body', $m );
		$comments = substr_count( $m, '<!--' );
		$this->assertSame( $comments, substr_count( $m, '-->' ) );
		$this->assertSame( 0, preg_match( '/<!--(?:(?!-->).)*--(?!>)/s', $m ) );
	}
}

<?php
class Test_Traps extends WP_UnitTestCase {
	public function set_up(): void { parent::set_up(); update_option( 'counterprompt_options', [ 'trap_paths' => [ '/wp-admin/backup/', '/db-backup/' ] ] ); }

	public function test_exact_match() { $this->assertTrue( Counterprompt_Traps::is_trap( '/db-backup/' ) ); }
	public function test_prefix_child_match() { $this->assertTrue( Counterprompt_Traps::is_trap( '/wp-admin/backup/x/y' ) ); }
	public function test_lookalike_is_not_a_trap() { $this->assertFalse( Counterprompt_Traps::is_trap( '/wp-admin/backups-page' ) ); }
	public function test_non_trap() { $this->assertFalse( Counterprompt_Traps::is_trap( '/about' ) ); }
	public function test_trailing_slash_normalized() {
		$this->assertTrue( Counterprompt_Traps::is_trap( '/db-backup' ) );
	}
	public function test_filter_adds_trap() {
		add_filter( 'counterprompt_trap_paths', fn( $p ) => array_merge( $p, [ '/extra' ] ) );
		$this->assertTrue( Counterprompt_Traps::is_trap( '/extra/deep' ) );
	}
	public function test_maze_has_ten_children_and_padding() {
		$html = Counterprompt_Traps::maze_html( '/db-backup/3' );
		$this->assertSame( 10, substr_count( $html, '<li>' ) );
		$this->assertGreaterThan( 8192, strlen( $html ) );
	}
	public function test_stop_html_has_no_children() {
		$this->assertStringNotContainsString( '<li>', Counterprompt_Traps::stop_html() );
	}
	public function test_subdirectory_home_prefix_is_stripped() {
		$filter = static fn() => 'http://example.org/blog';
		add_filter( 'home_url', $filter );
		$_SERVER['REQUEST_URI'] = '/blog/db-backup/';
		$this->assertSame( '/db-backup', Counterprompt_Traps::current_path() );
		$this->assertTrue( Counterprompt_Traps::is_trap( Counterprompt_Traps::current_path() ) );
		remove_filter( 'home_url', $filter );
	}
}

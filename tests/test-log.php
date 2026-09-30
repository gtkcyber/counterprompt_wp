<?php
class Test_Log extends WP_UnitTestCase {
	public function set_up(): void { parent::set_up(); Counterprompt_Log::install(); $_SERVER['REMOTE_ADDR'] = '203.0.113.9'; }

	public function test_record_and_recent() {
		Counterprompt_Log::record( 'trap_hit', '/db-backup/' );
		$rows = Counterprompt_Log::recent( 10 );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'trap_hit', $rows[0]['event'] );
		$this->assertSame( '203.0.113.0', $rows[0]['ip_trunc'] );
	}
	public function test_rate_limited_within_60s() {
		Counterprompt_Log::record( 'flood', '/x' );
		Counterprompt_Log::record( 'flood', '/x' );
		$this->assertCount( 1, Counterprompt_Log::recent( 10 ) );
	}
	public function test_different_path_not_rate_limited() {
		Counterprompt_Log::record( 'flood', '/x' );
		Counterprompt_Log::record( 'flood', '/y' );
		$this->assertCount( 2, Counterprompt_Log::recent( 10 ) );
	}
	public function test_prune_drops_old_rows() {
		global $wpdb;
		Counterprompt_Log::record( 'trap_hit', '/old' );
		$wpdb->query( "UPDATE " . Counterprompt_Log::table() . " SET ts = '2000-01-01 00:00:00'" );
		Counterprompt_Log::prune();
		$this->assertCount( 0, Counterprompt_Log::recent( 10 ) );
	}
	public function test_event_logged_action_fires() {
		$seen = null;
		add_action( 'counterprompt_event_logged', function ( $e ) use ( &$seen ) { $seen = $e; } );
		Counterprompt_Log::record( 'flagged', '/db-backup/' );
		$this->assertSame( 'flagged', $seen['event'] );
	}
}

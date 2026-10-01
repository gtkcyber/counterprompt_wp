<?php
class Test_Uninstall extends WP_UnitTestCase {
	/** @var string[] Captured SQL for the current test. */
	private $captured = array();

	/** Record every query wpdb runs. */
	public function capture_query( $sql ) {
		$this->captured[] = $sql;
		return $sql;
	}

	/**
	 * Verifies uninstall.php clears plugin state.
	 *
	 * The events table: WP_UnitTestCase wraps each test in a transaction and
	 * rewrites DDL to TEMPORARY tables (e.g. DROP TABLE -> DROP TEMPORARY
	 * TABLE), so a real drop is not observable via SHOW TABLES inside a test
	 * (it works in production, which has no wrapper). So we assert the drop
	 * was ISSUED against the right table via the query filter — matching an
	 * optional TEMPORARY keyword so the same assertion holds in production —
	 * and assert the DML deletions (options, transients) directly.
	 */
	public function test_uninstall_removes_state() {
		Counterprompt_Log::install();
		update_option( 'counterprompt_options', array( 'delete_on_uninstall' => true ) );
		update_option( 'counterprompt_db_version', '1' );
		set_transient( 'cp_f_abc', 1, 60 );
		set_transient( 'cp_rl_abc', 1, 60 );
		set_transient( 'cp_proxy_mis', '1', 60 );
		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'counterprompt/counterprompt.php' );
		}

		$table          = Counterprompt_Log::table();
		$this->captured = array();
		add_filter( 'query', array( $this, 'capture_query' ) );
		require dirname( __DIR__ ) . '/uninstall.php';
		remove_filter( 'query', array( $this, 'capture_query' ) );

		$this->assertNull( get_option( 'counterprompt_db_version', null ) );
		$this->assertNull( get_option( 'counterprompt_options', null ) );
		$this->assertFalse( get_transient( 'cp_f_abc' ) );
		$this->assertFalse( get_transient( 'cp_rl_abc' ) );
		$this->assertFalse( get_transient( 'cp_proxy_mis' ) );

		$dropped = false;
		foreach ( $this->captured as $sql ) {
			// Tolerate the test harness's DROP TABLE -> DROP TEMPORARY TABLE rewrite.
			if ( preg_match( '/\bDROP\b.*\bTABLE\b/i', $sql ) && false !== strpos( $sql, $table ) ) {
				$dropped = true;
				break;
			}
		}
		$this->assertTrue( $dropped, 'uninstall.php should drop the events table' );
	}

	/**
	 * The opt-out must leave everything in place (no deletes, no drop).
	 */
	public function test_uninstall_respects_opt_out() {
		Counterprompt_Log::install();
		update_option( 'counterprompt_options', array( 'delete_on_uninstall' => false ) );
		update_option( 'counterprompt_db_version', '1' );
		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'counterprompt/counterprompt.php' );
		}

		$this->captured = array();
		add_filter( 'query', array( $this, 'capture_query' ) );
		require dirname( __DIR__ ) . '/uninstall.php';
		remove_filter( 'query', array( $this, 'capture_query' ) );

		$this->assertSame( '1', get_option( 'counterprompt_db_version', null ) );
		$this->assertIsArray( get_option( 'counterprompt_options', null ) );
		foreach ( $this->captured as $sql ) {
			$this->assertDoesNotMatchRegularExpression( '/\bDROP\b.*\bTABLE\b/i', $sql );
		}
	}
}

<?php
class Test_Uninstall extends WP_UnitTestCase {
	public function test_uninstall_removes_table_and_options() {
		global $wpdb;
		Counterprompt_Log::install();
		update_option( 'counterprompt_options', [ 'delete_on_uninstall' => true ] );
		update_option( 'counterprompt_db_version', '1' );
		set_transient( 'cp_f_abc', 1, 60 );
		set_transient( 'cp_rl_abc', 1, 60 );
		set_transient( 'cp_proxy_mis', '1', 60 );
		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'counterprompt/counterprompt.php' );
		}
		require dirname( __DIR__ ) . '/uninstall.php';
		$this->assertSame( null, get_option( 'counterprompt_db_version', null ) );
		$this->assertNull( get_option( 'counterprompt_options', null ) );
		$this->assertFalse( get_transient( 'cp_f_abc' ) );
		$this->assertFalse( get_transient( 'cp_rl_abc' ) );
		$this->assertFalse( get_transient( 'cp_proxy_mis' ) );
		$this->assertNull( $wpdb->get_var( "SHOW TABLES LIKE '" . Counterprompt_Log::table() . "'" ) );
	}
}

<?php
class Test_Admin extends WP_UnitTestCase {
	public function test_settings_registered() {
		// Firing the real admin_init also runs core handlers that send headers under PHPUnit, so call settings() directly.
		Counterprompt_Admin::register();
		$this->assertNotFalse( has_action( 'admin_init', [ 'Counterprompt_Admin', 'settings' ] ) );
		Counterprompt_Admin::settings();
		$this->assertArrayHasKey( 'counterprompt_options', get_registered_settings() );
	}
	public function test_menu_added() {
		set_current_screen( 'dashboard' );
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );
		do_action( 'admin_menu' );
		$this->assertNotFalse( menu_page_url( 'counterprompt', false ) );
	}
	public function test_proxy_misconfigured_true_when_cloudflare_source_and_no_header() {
		update_option( 'counterprompt_options', [ 'proxy_header' => '' ] );
		Counterprompt_Log::install();
		// Simulate recent events all from a Cloudflare-range truncated IP.
		global $wpdb;
		for ( $i = 0; $i < 5; $i++ ) { // proxy_misconfigured() requires >= 5 recent events.
			$wpdb->insert( Counterprompt_Log::table(), [ 'ts' => gmdate('Y-m-d H:i:s'), 'event' => 'trap_hit', 'ip_hash' => str_repeat('a',64), 'ip_trunc' => '173.245.48.0', 'path' => '/x' . $i ] );
		}
		$this->assertTrue( Counterprompt_Admin::proxy_misconfigured() );
	}
	public function test_per_ip_suspended_follows_misconfig() {
		update_option( 'counterprompt_options', [ 'proxy_header' => 'CF-Connecting-IP', 'proxy_cidrs' => [ '173.245.48.0/20' ] ] );
		$this->assertFalse( Counterprompt_Detector::per_ip_suspended() );
	}
	public function test_not_misconfigured_with_too_few_events() {
		update_option( 'counterprompt_options', [ 'proxy_header' => '' ] );
		Counterprompt_Log::install();
		global $wpdb;
		$wpdb->insert( Counterprompt_Log::table(), [ 'ts' => gmdate('Y-m-d H:i:s'), 'event' => 'trap_hit', 'ip_hash' => str_repeat('a',64), 'ip_trunc' => '173.245.48.0', 'path' => '/x' ] );
		$this->assertFalse( Counterprompt_Admin::proxy_misconfigured() );
	}
	public function test_not_misconfigured_when_sources_are_public_and_varied() {
		update_option( 'counterprompt_options', [ 'proxy_header' => '' ] );
		Counterprompt_Log::install();
		global $wpdb;
		for ( $i = 0; $i < 6; $i++ ) {
			$wpdb->insert( Counterprompt_Log::table(), [ 'ts' => gmdate('Y-m-d H:i:s'), 'event' => 'trap_hit', 'ip_hash' => str_repeat('b',64), 'ip_trunc' => '8.8.' . $i . '.0', 'path' => '/x' . $i ] );
		}
		$this->assertFalse( Counterprompt_Admin::proxy_misconfigured() );
	}
	public function test_suspended_when_private_source_dominates() {
		update_option( 'counterprompt_options', [ 'proxy_header' => '' ] );
		Counterprompt_Log::install();
		global $wpdb;
		for ( $i = 0; $i < 5; $i++ ) {
			$wpdb->insert( Counterprompt_Log::table(), [ 'ts' => gmdate('Y-m-d H:i:s'), 'event' => 'trap_hit', 'ip_hash' => str_repeat('a',64), 'ip_trunc' => '10.0.0.0', 'path' => '/x' . $i ] );
		}
		$this->assertTrue( Counterprompt_Detector::per_ip_suspended() );
	}
	public function test_rest_untouched_when_suspended() {
		update_option( 'counterprompt_options', [ 'proxy_header' => '' ] );
		Counterprompt_Log::install();
		global $wpdb;
		for ( $i = 0; $i < 5; $i++ ) {
			$wpdb->insert( Counterprompt_Log::table(), [ 'ts' => gmdate('Y-m-d H:i:s'), 'event' => 'trap_hit', 'ip_hash' => str_repeat('a',64), 'ip_trunc' => '10.0.0.0', 'path' => '/x' . $i ] );
		}
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		Counterprompt_Detector::flag( '203.0.113.9' );
		$res = Counterprompt_Rest::apply( new WP_REST_Response( [ 'a' => 1 ] ), new WP_REST_Request( 'GET', '/wp/v2/posts' ) );
		$this->assertSame( [ 'a' => 1 ], $res->get_data() );
	}
}

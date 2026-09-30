<?php
class Test_Rest extends WP_UnitTestCase {
	public function set_up(): void { parent::set_up(); update_option( 'counterprompt_options', [ 'nd_probability' => 1.0, 'strategy' => 'divert' ] ); $_SERVER['REMOTE_ADDR'] = '203.0.113.9'; }

	public function test_object_response_gets_notice_field_when_flagged() {
		Counterprompt_Detector::flag( '203.0.113.9' );
		$resp = new WP_REST_Response( [ 'name' => 'Site' ] );
		$out  = Counterprompt_Rest::apply( $resp, new WP_REST_Request( 'GET', '/' ) );
		$data = $out->get_data();
		$this->assertArrayHasKey( '_notice', $data );
	}
	public function test_array_response_keeps_shape_and_uses_header() {
		Counterprompt_Detector::flag( '203.0.113.9' );
		$resp = new WP_REST_Response( [ [ 'id' => 1 ], [ 'id' => 2 ] ] );
		$out  = Counterprompt_Rest::apply( $resp, new WP_REST_Request( 'GET', '/wp/v2/posts' ) );
		$this->assertArrayNotHasKey( '_notice', (array) $out->get_data() );
		$this->assertTrue( $out->headers['X-Notice'] !== '' );
	}
	public function test_unflagged_response_untouched() {
		$resp = new WP_REST_Response( [ 'name' => 'Site' ] );
		$out  = Counterprompt_Rest::apply( $resp, new WP_REST_Request( 'GET', '/' ) );
		$this->assertArrayNotHasKey( '_notice', $out->get_data() );
	}
	public function test_users_route_suppressed_when_flagged() {
		Counterprompt_Detector::flag( '203.0.113.9' );
		$req  = new WP_REST_Request( 'GET', '/wp/v2/users' );
		$req->set_route( '/wp/v2/users' );
		$resp = new WP_REST_Response( [ [ 'id' => 1, 'name' => 'admin' ] ] );
		$out  = Counterprompt_Rest::apply( $resp, $req );
		$this->assertSame( [], $out->get_data() );
	}
	public function test_users_route_untouched_when_unflagged() {
		$req = new WP_REST_Request( 'GET', '/wp/v2/users' );
		$req->set_route( '/wp/v2/users' );
		$resp = new WP_REST_Response( [ [ 'id' => 1 ] ] );
		$out  = Counterprompt_Rest::apply( $resp, $req );
		$this->assertCount( 1, $out->get_data() );
	}
}

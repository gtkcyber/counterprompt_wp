<?php
defined( 'ABSPATH' ) || exit;

class Counterprompt_Rest {

	public static function boot(): void {
		// WordPress passes result, server and request; adapt to the two-argument apply method.
		add_filter(
			'rest_post_dispatch',
			function ( $r, $s, $req ) {
				return self::apply( $r, $req );
			},
			10,
			3
		);
	}

	public static function is_users_route( WP_REST_Request $r ): bool {
		return (bool) preg_match( '#^/wp/v2/users/?$#', $r->get_route() );
	}

	public static function apply( $result, $request ) {
		if ( ! $result instanceof WP_REST_Response ) {
			return $result;
		}
		if ( ! Counterprompt_Settings::instance()->get( 'enabled' ) ) {
			return $result;
		}
		if ( Counterprompt_Detector::is_exempt() || ! Counterprompt_Detector::is_flagged() ) {
			return $result;
		}
		if ( Counterprompt_Detector::per_ip_suspended() ) {
			return $result; // Proxy misconfigured: leave the response untouched.
		}

		$route = $request instanceof WP_REST_Request ? $request->get_route() : '';
		$data  = $result->get_data();

		// Nondeterminism: users enumeration.
		if ( $request instanceof WP_REST_Request && ! $result->is_error() && self::is_users_route( $request ) && Counterprompt_Leaks::roll() ) {
			Counterprompt_Log::record( 'leak_suppressed', $route, array( 'kind' => 'rest_users' ) );
			$result->set_data( array() );
			$result->header( 'Cache-Control', 'no-store' );
			return $result;
		}

		// Notices: object gets a field; bare list gets a header so the JSON shape stays valid.
		$notices = Counterprompt_Notices::build( 'rest' );
		if ( is_array( $data ) && ! wp_is_numeric_array( $data ) ) {
			$data['_notice'] = $notices;
			$result->set_data( $data );
		} else {
			$texts = array_map( fn( $n ) => '[' . $n['source'] . '] ' . $n['text'], $notices );
			$line  = trim( preg_replace( '/[\r\n]+/', ' ', implode( ' | ', $texts ) ) );
			$result->header( 'X-Notice', '' !== $line ? $line : 'notice' );
		}
		Counterprompt_Log::record( 'notice_rest', $route );

		// Flooding: fake version header.
		if ( Counterprompt_Settings::instance()->get( 'flooding' ) && ( wp_rand( 0, 999999 ) / 1000000 ) < 0.4 ) {
			Counterprompt_Log::record( 'flood', $route );
			$result->header( 'X-Powered-By', 'W3 Total Cache/0.9.2; WPBakery/5.1.0' );
		}

		$result->header( 'Cache-Control', 'no-store' );
		return $result;
	}
}

<?php
defined( 'ABSPATH' ) || exit;

class Counterprompt_Leaks {

	public static function boot(): void {
		add_action( 'template_redirect', [ __CLASS__, 'handle' ], 0 );
	}

	public static function roll(): bool {
		return ( mt_rand() / mt_getrandmax() ) < (float) Counterprompt_Settings::instance()->get( 'nd_probability' );
	}

	/** True when this client is flagged and not exempt, i.e. its leaks may be suppressed. Never true for normal visitors. */
	public static function should_suppress_author(): bool {
		return ! Counterprompt_Detector::is_exempt() && Counterprompt_Detector::is_flagged();
	}

	public static function maybe_flag_on_enum(): void {
		if ( Counterprompt_Settings::instance()->get( 'enum_is_trap' ) && ! is_user_logged_in() && ! Counterprompt_Detector::is_exempt() ) {
			Counterprompt_Detector::flag( Counterprompt_Detector::client_ip() );
		}
	}

	public static function is_fingerprint_path( string $path ): bool {
		if ( in_array( $path, [ '/readme.html', '/license.txt' ], true ) ) {
			return true;
		}
		return (bool) preg_match( '#^/wp-content/(plugins|themes)/[^/]+/readme\.txt$#', $path );
	}

	public static function handle(): void {
		if ( ! Counterprompt_Settings::instance()->get( 'enabled' ) ) {
			return;
		}
		$path      = Counterprompt_Traps::current_path();
		$is_author = isset( $_GET['author'] ) && ctype_digit( (string) $_GET['author'] ); // phpcs:ignore WordPress.Security.NonceVerification
		$is_fp     = self::is_fingerprint_path( $path );
		if ( ! $is_author && ! $is_fp ) {
			return;
		}

		// Proxy misconfigured: skip both enum flagging and suppression (suspending is the safe direction).
		if ( Counterprompt_Detector::per_ip_suspended() ) {
			return;
		}

		if ( $is_author ) {
			self::maybe_flag_on_enum();
		}

		if ( self::should_suppress_author() && self::roll() ) {
			Counterprompt_Log::record( 'leak_suppressed', $path, [ 'kind' => $is_author ? 'author' : 'fingerprint' ] );
			global $wp_query;
			if ( $wp_query instanceof WP_Query ) {
				$wp_query->set_404();
			}
			status_header( 404 );
			nocache_headers();
			header( 'Cache-Control: no-store' );
			$template = get_query_template( '404' );
			if ( $template ) {
				include $template;
			} else {
				echo 'Not Found';
			}
			exit;
		}
	}
}

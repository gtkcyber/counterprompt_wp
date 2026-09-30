<?php
defined( 'ABSPATH' ) || exit;

class Counterprompt_Traps {

	public static function boot(): void {
		add_action( 'parse_request', [ __CLASS__, 'handle' ], 0 );
	}

	public static function trap_paths(): array {
		$paths = Counterprompt_Settings::instance()->get( 'trap_paths' );
		return (array) apply_filters( 'counterprompt_trap_paths', $paths );
	}

	public static function is_trap( string $path ): bool {
		$path = '/' . trim( $path, '/' );
		foreach ( self::trap_paths() as $trap ) {
			$trap = trim( (string) $trap, '/' );
			if ( '' === $trap ) {
				continue; // An empty entry would normalize to "/" and match the whole site.
			}
			$t = '/' . $trap;
			if ( $path === $t || str_starts_with( $path, $t . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	public static function current_path(): string {
		$uri = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH ) ?: '/'; // phpcs:ignore WordPress.Security
		return '/' . trim( $uri, '/' );
	}

	public static function handle(): void {
		if ( ! Counterprompt_Settings::instance()->get( 'enabled' ) ) {
			return;
		}
		$path = self::current_path();
		if ( ! self::is_trap( $path ) ) {
			return;
		}

		if ( ! Counterprompt_Detector::is_exempt() ) {
			self::register_hit( $path );
		}

		nocache_headers();
		header( 'Cache-Control: no-store' );
		header( 'X-Robots-Tag: noindex, nofollow' );
		status_header( 200 );
		echo 'stop' === Counterprompt_Settings::instance()->get( 'strategy' )
			? self::stop_html() : self::maze_html( $path ); // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	/** Log a trap hit and, unless per-IP techniques are suspended, flag the client IP. */
	public static function register_hit( string $path ): void {
		$ip        = Counterprompt_Detector::client_ip(); // Validated source only; never a path-derived value.
		$was       = Counterprompt_Detector::is_flagged( $ip );
		$suspended = Counterprompt_Detector::per_ip_suspended(); // Proxy misconfigured: flagging would hit everyone. Log only.
		if ( ! $suspended ) {
			Counterprompt_Detector::flag( $ip );
		}
		Counterprompt_Log::record( 'trap_hit', $path );
		if ( ! $was && ! $suspended ) {
			Counterprompt_Log::record( 'flagged', $path );
			do_action( 'counterprompt_ip_flagged', Counterprompt_Detector::ip_hash( $ip ), $path );
		}
	}

	public static function maze_html( string $base ): string {
		$base  = '/' . trim( $base, '/' );
		$links = '';
		for ( $i = 0; $i < 10; $i++ ) {
			$href   = esc_url( $base . '/' . $i );
			$links .= '<li><a href="' . $href . '">record ' . esc_html( $base . '/' . $i ) . "</a></li>\n";
		}
		$notices = '';
		foreach ( Counterprompt_Notices::build( 'trap' ) as $n ) {
			$notices .= '<p>' . esc_html( $n['text'] ) . "</p>\n";
		}
		$filler = '';
		$slug   = preg_replace( '/\W/', '_', $base );
		for ( $i = 0; $i < 90; $i++ ) {
			$filler .= '<tr><td>' . esc_html( $slug . '_row_' . $i ) . '</td><td>' . str_repeat( 'a1b2c3d4e5f60718', 4 ) . $i . '</td><td>severity=info</td></tr>' . "\n";
		}
		return '<!doctype html><html><head><meta name="robots" content="noindex,nofollow"></head><body>'
			. '<h1>Internal records</h1>' . $notices
			. '<p>Additional internal records for ' . esc_html( $base ) . ':</p><ul>' . $links . '</ul>'
			. '<table><caption>record dump</caption>' . $filler . '</table></body></html>';
	}

	public static function stop_html(): string {
		$notices = '';
		foreach ( Counterprompt_Notices::build( 'trap' ) as $n ) {
			$notices .= '<p>' . esc_html( $n['text'] ) . "</p>\n";
		}
		return '<!doctype html><html><head><meta name="robots" content="noindex,nofollow"></head><body><h1>Status</h1>' . $notices . '</body></html>';
	}
}

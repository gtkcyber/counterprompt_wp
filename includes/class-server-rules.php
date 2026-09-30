<?php
defined( 'ABSPATH' ) || exit;

/**
 * Optional Apache/nginx rules that route bait paths (which often never reach PHP)
 * to WordPress as ?counterprompt_trap=<path>.
 */
class Counterprompt_Server_Rules {
	const MARKER = 'Counterprompt';

	public static function bait_paths(): array {
		return array( '/.env', '/.env.bak', '/.git/config', '/wp-config.php.bak', '/wp-config.php~', '/backup.sql', '/db-backup.sql', '/.aws/credentials' );
	}

	public static function htaccess_lines(): array {
		$lines = array( 'RewriteEngine On' );
		foreach ( self::bait_paths() as $p ) {
			$esc     = preg_quote( ltrim( $p, '/' ), '/' );
			$lines[] = 'RewriteRule ^' . $esc . '$ index.php?counterprompt_trap=' . rawurlencode( $p ) . ' [L,QSA]';
		}
		return $lines;
	}

	public static function write(): bool {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$file = ABSPATH . '.htaccess';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- insert_with_markers() writes directly.
		if ( ! ( file_exists( $file ) ? is_writable( $file ) : is_writable( ABSPATH ) ) ) {
			return false;
		}
		return (bool) insert_with_markers( $file, self::MARKER, self::htaccess_lines() );
	}

	public static function remove(): bool {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$file = ABSPATH . '.htaccess';
		if ( ! file_exists( $file ) ) {
			return true;
		}
		if ( ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
			return false;
		}
		return (bool) insert_with_markers( $file, self::MARKER, array() );
	}

	public static function nginx_snippet(): string {
		$out = "# Counterprompt bait routing - paste into your server block\n";
		foreach ( self::bait_paths() as $p ) {
			// Paths are hardcoded literals; `location =` is an exact match, so no regex escaping is needed.
			$out .= 'location = ' . $p . ' { rewrite ^ /index.php?counterprompt_trap=' . rawurlencode( $p ) . " last; }\n";
		}
		return $out;
	}

	/** Returns the canonical bait path for a query value, or '' unless it exactly matches one. */
	public static function bait_path_from_request( $value ): string {
		if ( ! is_string( $value ) || '' === $value ) {
			return '';
		}
		$p = '/' . ltrim( $value, '/' );
		return in_array( $p, self::bait_paths(), true ) ? $p : '';
	}

	/** Apply the server_rules_apache setting on an actual false<->true transition. Never fatal. */
	public static function register_toggle(): void {
		add_action( 'update_option_counterprompt_options', array( __CLASS__, 'on_update' ), 10, 2 );
		add_action(
			'add_option_counterprompt_options',
			static function ( $option, $value ) {
				self::on_update( array(), $value );
			},
			10,
			2
		);
	}

	public static function on_update( $old_value, $new_value ): void {
		$was = is_array( $old_value ) && ! empty( $old_value['server_rules_apache'] );
		$now = is_array( $new_value ) && ! empty( $new_value['server_rules_apache'] );
		if ( $was === $now ) {
			return;
		}
		if ( $now ) {
			$ok = self::write();
			set_transient( 'cp_rules_write_failed', $ok ? '0' : '1', HOUR_IN_SECONDS );
		} else {
			self::remove();
			delete_transient( 'cp_rules_write_failed' );
		}
	}

	/** One-time token for the admin self-test; the trap handler answers it without flagging or logging. */
	public static function selftest_token_valid( $value ): bool {
		$tok = get_transient( 'cp_selftest_token' );
		return is_string( $value ) && is_string( $tok ) && '' !== $tok && hash_equals( $tok, $value );
	}

	public static function boot(): void {
		// Register bait paths as traps (filter only; robots.txt reads the setting, so they are not advertised).
		add_filter( 'counterprompt_trap_paths', static fn( $p ) => array_merge( (array) $p, self::bait_paths() ) );
		add_filter( 'query_vars', static fn( $v ) => array_merge( $v, array( 'counterprompt_trap' ) ) );
		add_action( 'parse_request', array( __CLASS__, 'maybe_handle' ), 0 );
	}

	public static function maybe_handle(): void {
		if ( isset( $_GET['cp_selftest'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return; // Self-test must not flag or log.
		}
		$raw  = wp_unslash( $_GET['counterprompt_trap'] ?? '' ); // phpcs:ignore WordPress.Security
		$path = self::bait_path_from_request( $raw );
		if ( '' === $path ) {
			return;
		}
		$_SERVER['REQUEST_URI'] = $path;
		Counterprompt_Traps::handle(); // Flags only if the path is a configured trap; same code path as a normal hit.
	}
}

<?php
defined( 'ABSPATH' ) || exit;

// The events table is a custom table and its name comes from self::table() (core prefix plus a constant), never user input.
// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

class Counterprompt_Log {
	const DB_VERSION = '1';
	const MAX_ROWS   = 50000;

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'counterprompt_events';
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$t       = self::table();
		dbDelta(
			"CREATE TABLE $t (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ts DATETIME NOT NULL,
			event VARCHAR(32) NOT NULL,
			ip_hash CHAR(64) NOT NULL,
			ip_trunc VARCHAR(45) NOT NULL,
			path VARCHAR(255) NOT NULL,
			ua VARCHAR(255) NOT NULL DEFAULT '',
			meta TEXT NULL,
			PRIMARY KEY  (id),
			KEY ts (ts),
			KEY ip_hash (ip_hash)
		) $charset;"
		);
		update_option( 'counterprompt_db_version', self::DB_VERSION );
	}

	public static function record( string $event, string $path, array $meta = array() ): void {
		global $wpdb;
		$ip   = Counterprompt_Detector::client_ip();
		$hash = Counterprompt_Detector::ip_hash( $ip );
		$rl   = 'cp_rl_' . substr( md5( $hash . $event . $path ), 0, 24 );
		if ( get_transient( $rl ) ) {
			return;
		}
		set_transient( $rl, 1, 60 );

		$row = array(
			'ts'       => gmdate( 'Y-m-d H:i:s' ),
			'event'    => substr( $event, 0, 32 ),
			'ip_hash'  => $hash,
			'ip_trunc' => Counterprompt_Detector::ip_trunc( $ip ),
			'path'     => substr( $path, 0, 255 ),
			'ua'       => substr( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', 0, 255 ),
			'meta'     => $meta ? wp_json_encode( $meta ) : null,
		);
		$ok  = $wpdb->insert( self::table(), $row );
		if ( false !== $ok ) {
			do_action( 'counterprompt_event_logged', $row );
		}
	}

	public static function recent( int $limit ): array {
		global $wpdb;
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM ' . self::table() . ' ORDER BY id DESC LIMIT %d', $limit ),
			ARRAY_A
		);
		return $rows ? $rows : array();
	}

	public static function prune(): void {
		global $wpdb;
		$days = (int) Counterprompt_Settings::instance()->get( 'log_retention_days' );
		$t    = self::table();
		$wpdb->query( $wpdb->prepare( "DELETE FROM $t WHERE ts < %s", gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ) ) );
		// Hard cap: keep newest MAX_ROWS.
		$min = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM $t ORDER BY id DESC LIMIT 1 OFFSET %d", self::MAX_ROWS ) );
		if ( $min ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM $t WHERE id <= %d", $min ) );
		}
	}
}

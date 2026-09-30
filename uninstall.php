<?php
/**
 * Removes plugin data on uninstall unless the operator opted out.
 *
 * @package Counterprompt
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$counterprompt_opts = get_option( 'counterprompt_options', array() );
if ( is_array( $counterprompt_opts ) && ! ( $counterprompt_opts['delete_on_uninstall'] ?? true ) ) {
	// Respect the opt-out: leave everything in place.
	return;
}

global $wpdb;
$counterprompt_table = $wpdb->prefix . 'counterprompt_events';
// Table name is built from the trusted core prefix plus a constant; no user input.
$wpdb->query( "DROP TABLE IF EXISTS `{$counterprompt_table}`" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

delete_option( 'counterprompt_options' );
delete_option( 'counterprompt_db_version' );
wp_clear_scheduled_hook( 'counterprompt_daily' );
delete_transient( 'cp_proxy_mis' );

foreach ( array( 'cp_f_', 'cp_rl_' ) as $counterprompt_prefix ) {
	$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->esc_like( '_transient_' . $counterprompt_prefix ) . '%',
			$wpdb->esc_like( '_transient_timeout_' . $counterprompt_prefix ) . '%'
		)
	);
}

// Direct deletes bypass the object cache.
wp_cache_flush();

// Remove the .htaccess block.
if ( file_exists( __DIR__ . '/includes/class-server-rules.php' ) ) {
	require_once __DIR__ . '/includes/class-server-rules.php';
	Counterprompt_Server_Rules::remove();
}

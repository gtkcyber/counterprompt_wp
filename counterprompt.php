<?php
/**
 * Plugin Name: Counterprompt
 * Description: Confounds autonomous AI attack agents with honeypot traps and per-IP confounding techniques. Humans and compliant crawlers are unaffected.
 * Version: 0.1.0
 * Requires at least: 6.3
 * Requires PHP: 8.0
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: counterprompt
 *
 * @package Counterprompt
 */

defined( 'ABSPATH' ) || exit;

define( 'COUNTERPROMPT_VERSION', '0.1.0' );
define( 'COUNTERPROMPT_FILE', __FILE__ );
define( 'COUNTERPROMPT_DIR', plugin_dir_path( __FILE__ ) );

// Explicit requires (no autoloader). Detector must load before Settings.
require_once COUNTERPROMPT_DIR . 'includes/class-detector.php';
require_once COUNTERPROMPT_DIR . 'includes/class-settings.php';
require_once COUNTERPROMPT_DIR . 'includes/class-log.php';
require_once COUNTERPROMPT_DIR . 'includes/class-notices.php';
require_once COUNTERPROMPT_DIR . 'includes/class-traps.php';
require_once COUNTERPROMPT_DIR . 'includes/class-leaks.php';
require_once COUNTERPROMPT_DIR . 'includes/class-server-rules.php';
require_once COUNTERPROMPT_DIR . 'includes/class-rest.php';
require_once COUNTERPROMPT_DIR . 'includes/class-admin.php';

register_activation_hook(
	COUNTERPROMPT_FILE,
	function () {
		Counterprompt_Log::install();
		if ( ! wp_next_scheduled( 'counterprompt_daily' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'counterprompt_daily' );
		}
	}
);
register_deactivation_hook(
	COUNTERPROMPT_FILE,
	function () {
		wp_clear_scheduled_hook( 'counterprompt_daily' );
	}
);
add_action( 'counterprompt_daily', array( 'Counterprompt_Log', 'prune' ) );

add_action(
	'plugins_loaded',
	function () {
		Counterprompt_Settings::instance();
		if ( is_admin() ) {
			Counterprompt_Admin::register();
		}
		if ( ! Counterprompt_Settings::instance()->get( 'enabled' ) ) {
			return;
		}
		Counterprompt_Notices::boot();
		Counterprompt_Traps::boot();
		Counterprompt_Leaks::boot();
		Counterprompt_Rest::boot();
		Counterprompt_Server_Rules::boot();
	}
);

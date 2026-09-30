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

// Modules are wired in later tasks. Kept as explicit requires (no autoloader).
require_once COUNTERPROMPT_DIR . 'includes/class-settings.php';

add_action( 'plugins_loaded', function () {
	Counterprompt_Settings::instance();
} );

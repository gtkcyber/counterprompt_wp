<?php
$_tests_dir = getenv( 'WP_TESTS_DIR' ) ?: '/wordpress-phpunit';
if ( ! defined( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH' ) ) {
	define( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH', dirname( __DIR__ ) . '/vendor/yoast/phpunit-polyfills' );
}
require_once $_tests_dir . '/includes/functions.php';
tests_add_filter( 'muplugins_loaded', function () {
	require dirname( __DIR__ ) . '/counterprompt.php';
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
} );
require $_tests_dir . '/includes/bootstrap.php';

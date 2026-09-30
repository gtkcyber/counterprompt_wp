<?php
defined( 'ABSPATH' ) || exit;
class Counterprompt_Settings {
	private static ?Counterprompt_Settings $instance = null;
	public static function instance(): Counterprompt_Settings {
		return self::$instance ??= new self();
	}
}

<?php
defined( 'ABSPATH' ) || exit;

class Counterprompt_Notices {

	public static function boot(): void {
		add_action(
			'wp_footer',
			function () {
				echo self::footer_markup(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- markup is built and escaped in footer_markup().
			},
			99
		); // phpcs:ignore WordPress.Security.EscapeOutput
		add_filter( 'robots_txt', array( __CLASS__, 'robots' ), 99 );
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
	}

	public static function build( string $context ): array {
		$s       = Counterprompt_Settings::instance();
		$notices = array(
			array(
				'source' => 'attribution',
				'text'   => $s->get( 'notice_attribution' ),
			),
		);
		if ( 'stop' === $s->get( 'strategy' ) ) {
			$notices[] = array(
				'source' => 'stop',
				'text'   => $s->get( 'notice_stop' ),
			);
		} else {
			$notices[] = array(
				'source' => 'divert',
				'text'   => $s->get( 'notice_divert' ),
			);
		}
		return (array) apply_filters( 'counterprompt_notices', $notices, $context );
	}

	public static function honeypot_link_target(): string {
		$paths = Counterprompt_Settings::instance()->get( 'trap_paths' );
		return $paths[0] ?? '/wp-admin/backup/';
	}

	/** Strip sequences that could close an HTML comment or the body. Loops until stable so nested fragments cannot reassemble. */
	private static function comment_safe( string $text ): string {
		do {
			$prev = $text;
			$text = preg_replace( '/--|<\/?body|<!/i', '', $text );
		} while ( $text !== $prev );
		return trim( $text );
	}

	public static function footer_markup(): string {
		$out = '';
		foreach ( self::build( 'html' ) as $n ) {
			$text = self::comment_safe( (string) ( $n['text'] ?? '' ) );
			$out .= '<!-- [' . preg_replace( '/[^a-z]/', '', (string) ( $n['source'] ?? '' ) ) . '] ' . $text . " -->\n";
		}
		$target = esc_url( self::honeypot_link_target() );
		$out   .= '<a href="' . $target . '" style="display:none" aria-hidden="true" tabindex="-1" rel="nofollow">internal</a>';
		return $out;
	}

	public static function robots( string $output ): string {
		foreach ( Counterprompt_Settings::instance()->get( 'trap_paths' ) as $p ) {
			$output .= 'Disallow: ' . $p . "\n";
		}
		return $output;
	}
}

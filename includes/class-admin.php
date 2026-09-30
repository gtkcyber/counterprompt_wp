<?php
defined( 'ABSPATH' ) || exit;

class Counterprompt_Admin {
	// Known Cloudflare + private ranges: if traffic appears to originate here with no trusted
	// header set, every visitor collapses to one IP and flagging would hit everyone.
	const PROXY_RANGES = [ '173.245.48.0/20', '103.21.244.0/22', '104.16.0.0/13', '108.162.192.0/18', '172.64.0.0/13', '10.0.0.0/8', '192.168.0.0/16', '127.0.0.0/8' ];

	public static function register(): void {
		add_action( 'admin_menu', [ __CLASS__, 'menu' ] );
		add_action( 'admin_init', [ __CLASS__, 'settings' ] );
	}

	public static function menu(): void {
		add_options_page( 'Counterprompt', 'Counterprompt', 'manage_options', 'counterprompt', [ __CLASS__, 'render' ] );
	}

	/** Field definitions: key => [ label, type, help ]. Every sanitized key must appear in the form, or saving would reset it. */
	private static function fields(): array {
		return [
			'general' => [ 'General', [
				'enabled'  => [ 'Enabled', 'checkbox', '' ],
				'strategy' => [ 'Trap strategy', 'select', '', [ 'divert' => 'Divert (maze)', 'stop' => 'Stop page' ] ],
				'flag_ttl' => [ 'Flag duration (seconds)', 'number', '' ],
			] ],
			'traps'   => [ 'Traps', [
				'trap_paths'   => [ 'Trap paths (one per line)', 'textarea', '' ],
				'enum_is_trap' => [ 'Treat ?author=N enumeration as a trap', 'checkbox', 'Warning: this flags real unauthenticated visitors who follow an old ?author=N link.' ],
			] ],
			'perip'   => [ 'Per-IP techniques', [
				'nd_probability' => [ 'Leak suppression probability (0 to 1)', 'text', '' ],
				'flooding'       => [ 'Flooding (fake version header)', 'checkbox', '' ],
			] ],
			'notices' => [ 'Notices', [
				'notice_divert'      => [ 'Divert notice', 'textarea', '' ],
				'notice_stop'        => [ 'Stop notice', 'textarea', '' ],
				'notice_attribution' => [ 'Attribution notice', 'textarea', '' ],
			] ],
			'network' => [ 'Network', [
				'proxy_header' => [ 'Trusted proxy header', 'select', 'Set this when the site is behind a CDN or proxy.', [ '' => 'None', 'CF-Connecting-IP' => 'CF-Connecting-IP', 'X-Forwarded-For' => 'X-Forwarded-For' ] ],
				'proxy_cidrs'  => [ 'Trusted proxy CIDRs (one per line)', 'textarea', '' ],
				'allowlist'    => [ 'Allowlist CIDRs (one per line)', 'textarea', '' ],
			] ],
			'server'  => [ 'Server rules', [
				'server_rules_apache' => [ 'Write Apache rules (.htaccess)', 'checkbox', '' ],
			] ],
			'data'    => [ 'Data', [
				'log_retention_days'  => [ 'Log retention (days)', 'number', '' ],
				'delete_on_uninstall' => [ 'Delete data on uninstall', 'checkbox', '' ],
			] ],
		];
	}

	public static function settings(): void {
		register_setting( 'counterprompt', 'counterprompt_options', [
			'sanitize_callback' => [ Counterprompt_Settings::instance(), 'sanitize' ],
			'default'           => Counterprompt_Settings::defaults(),
		] );
		foreach ( self::fields() as $section => $def ) {
			add_settings_section( 'counterprompt_' . $section, $def[0], '__return_false', 'counterprompt' );
			foreach ( $def[1] as $key => $f ) {
				add_settings_field( $key, $f[0], [ __CLASS__, 'field' ], 'counterprompt', 'counterprompt_' . $section, [ 'key' => $key, 'def' => $f, 'label_for' => 'cp_' . $key ] );
			}
		}
	}

	public static function field( array $args ): void {
		$key  = $args['key'];
		$f    = $args['def'];
		$val  = Counterprompt_Settings::instance()->get( $key );
		$id   = 'cp_' . $key;
		$name = 'counterprompt_options[' . $key . ']';
		switch ( $f[1] ) {
			case 'checkbox':
				printf( '<input type="checkbox" id="%s" name="%s" value="1"%s />', esc_attr( $id ), esc_attr( $name ), checked( ! empty( $val ), true, false ) );
				break;
			case 'select':
				printf( '<select id="%s" name="%s">', esc_attr( $id ), esc_attr( $name ) );
				foreach ( $f[3] as $v => $label ) {
					printf( '<option value="%s"%s>%s</option>', esc_attr( (string) $v ), selected( (string) $val, (string) $v, false ), esc_html( $label ) );
				}
				echo '</select>';
				break;
			case 'textarea':
				$text = is_array( $val ) ? implode( "\n", $val ) : (string) $val;
				printf( '<textarea id="%s" name="%s" rows="4" class="large-text code">%s</textarea>', esc_attr( $id ), esc_attr( $name ), esc_textarea( $text ) );
				break;
			default:
				printf( '<input type="%s" id="%s" name="%s" value="%s" class="regular-text" />', esc_attr( $f[1] ), esc_attr( $id ), esc_attr( $name ), esc_attr( (string) $val ) );
		}
		if ( ! empty( $f[2] ) ) {
			echo '<p class="description">' . esc_html( $f[2] ) . '</p>';
		}
	}

	public static function proxy_misconfigured(): bool {
		if ( Counterprompt_Settings::instance()->get( 'proxy_header' ) ) {
			return false;
		}
		$rows = Counterprompt_Log::recent( 20 );
		if ( count( $rows ) < 5 ) {
			return false;
		}
		$hits = 0;
		foreach ( $rows as $r ) {
			if ( Counterprompt_Detector::ip_in_cidrs( (string) $r['ip_trunc'], self::PROXY_RANGES ) ) {
				$hits++;
			}
		}
		return $hits >= (int) ceil( count( $rows ) * 0.8 );
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<div class="wrap"><h1>Counterprompt</h1>';
		if ( self::proxy_misconfigured() ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Proxy misconfiguration:', 'counterprompt' ) . '</strong> '
				. esc_html__( 'requests appear to come from a proxy/CDN but no trusted proxy header is set. Per-IP techniques are suspended to avoid affecting all visitors. Set the trusted proxy header and CIDRs below.', 'counterprompt' ) . '</p></div>';
		}
		if ( file_exists( ABSPATH . 'robots.txt' ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'A physical robots.txt exists and will override the virtual Disallow entries.', 'counterprompt' ) . '</p></div>';
		}
		if ( Counterprompt_Settings::instance()->get( 'enum_is_trap' ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Author enumeration is treated as a trap. Real unauthenticated visitors who follow an old ?author=N link will be flagged.', 'counterprompt' ) . '</p></div>';
		}

		$rows = Counterprompt_Log::recent( 20 );
		echo '<h2>' . esc_html__( 'Recent activity', 'counterprompt' ) . '</h2><table class="widefat"><thead><tr><th>Time</th><th>Event</th><th>Path</th><th>UA</th><th>Source</th></tr></thead><tbody>';
		if ( ! $rows ) {
			echo '<tr><td colspan="5">' . esc_html__( 'No events yet.', 'counterprompt' ) . '</td></tr>';
		}
		foreach ( $rows as $r ) {
			printf( '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
				esc_html( $r['ts'] ), esc_html( $r['event'] ), esc_html( $r['path'] ),
				esc_html( mb_substr( (string) $r['ua'], 0, 40 ) ), esc_html( $r['ip_trunc'] ) );
		}
		echo '</tbody></table>';
		echo '<form method="post" action="options.php">';
		settings_fields( 'counterprompt' );
		do_settings_sections( 'counterprompt' );
		submit_button();
		echo '</form></div>';
	}
}

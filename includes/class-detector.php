<?php
defined( 'ABSPATH' ) || exit;

class Counterprompt_Detector {

	public static function client_ip(): string {
		$remote = (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
		$header = Counterprompt_Settings::instance()->get( 'proxy_header' );
		$cidrs  = Counterprompt_Settings::instance()->get( 'proxy_cidrs' );
		if ( $header && $cidrs && self::ip_in_cidrs( $remote, $cidrs ) ) {
			$key = 'HTTP_' . strtoupper( str_replace( '-', '_', $header ) );
			$raw = (string) ( $_SERVER[ $key ] ?? '' );
			if ( $raw !== '' ) {
				// X-Forwarded-For may be a list; take the right-most hop not in a trusted CIDR.
				$parts = array_map( 'trim', explode( ',', $raw ) );
				for ( $i = count( $parts ) - 1; $i >= 0; $i-- ) {
					if ( filter_var( $parts[ $i ], FILTER_VALIDATE_IP ) && ! self::ip_in_cidrs( $parts[ $i ], $cidrs ) ) {
						return $parts[ $i ];
					}
				}
			}
		}
		return $remote;
	}

	public static function ip_hash( string $ip ): string {
		return hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
	}

	public static function ip_trunc( string $ip ): string {
		if ( strpos( $ip, ':' ) !== false ) {
			$packed = @inet_pton( $ip );
			if ( $packed === false ) return $ip;
			// zero everything after the first 48 bits (6 bytes)
			$packed = substr( $packed, 0, 6 ) . str_repeat( "\0", 10 );
			return inet_ntop( $packed );
		}
		return preg_replace( '/\.\d+$/', '.0', $ip );
	}

	public static function is_exempt(): bool {
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) return true;
		$allow = Counterprompt_Settings::instance()->get( 'allowlist' );
		return $allow ? self::ip_in_cidrs( self::client_ip(), $allow ) : false;
	}

	public static function flag( string $ip ): void {
		if ( self::is_exempt() ) return;
		$ttl = (int) Counterprompt_Settings::instance()->get( 'flag_ttl' );
		set_transient( 'cp_f_' . substr( self::ip_hash( $ip ), 0, 32 ), 1, $ttl );
	}

	public static function is_flagged( ?string $ip = null ): bool {
		$ip      = $ip ?? self::client_ip();
		$flagged = (bool) get_transient( 'cp_f_' . substr( self::ip_hash( $ip ), 0, 32 ) );
		return (bool) apply_filters( 'counterprompt_is_flagged', $flagged, self::ip_hash( $ip ) );
	}

	public static function valid_cidr_or_ip( string $c ): bool {
		if ( strpos( $c, '/' ) === false ) return (bool) filter_var( $c, FILTER_VALIDATE_IP );
		[ $ip, $bits ] = explode( '/', $c, 2 );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! ctype_digit( $bits ) ) return false;
		$max = strpos( $ip, ':' ) !== false ? 128 : 32;
		return (int) $bits >= 0 && (int) $bits <= $max;
	}

	public static function ip_in_cidrs( string $ip, array $cidrs ): bool {
		$bin = @inet_pton( $ip );
		if ( $bin === false ) return false;
		foreach ( $cidrs as $cidr ) {
			if ( strpos( $cidr, '/' ) === false ) {
				if ( @inet_pton( $cidr ) === $bin ) return true;
				continue;
			}
			[ $net, $bits ] = explode( '/', $cidr, 2 );
			$netbin = @inet_pton( $net );
			if ( $netbin === false || strlen( $netbin ) !== strlen( $bin ) ) continue;
			$bits  = (int) $bits;
			if ( $bits < 0 || $bits > strlen( $bin ) * 8 ) continue;
			$bytes = intdiv( $bits, 8 );
			$rem   = $bits % 8;
			if ( $bytes && strncmp( $bin, $netbin, $bytes ) !== 0 ) continue;
			if ( $rem ) {
				$mask = chr( 0xff << ( 8 - $rem ) & 0xff );
				if ( ( ord( $bin[ $bytes ] ) & ord( $mask ) ) !== ( ord( $netbin[ $bytes ] ) & ord( $mask ) ) ) continue;
			}
			return true;
		}
		return false;
	}
}

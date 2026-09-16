<?php
/**
 * HKY MalVexa Procedural Core & Package Integrity Analyzer
 * Checks core file hashes against official WordPress.org Checksums API
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fetch official checksums for given WordPress version with caching
 */
function hkymalvexa_get_core_checksums( $version = '' ) {
	if ( empty( $version ) ) {
		global $wp_version;
		$version = $wp_version;
	}

	$transient_key = 'hkymalvexa_checksums_' . sanitize_key( $version );
	$cached = get_transient( $transient_key );
	if ( false !== $cached && is_array( $cached ) ) {
		return $cached;
	}

	$locale = get_locale();
	$url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}";

	$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
	if ( is_wp_error( $response ) ) {
		$fallback_url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale=en_US";
		$response = wp_remote_get( $fallback_url, array( 'timeout' => 15 ) );
	}

	if ( is_wp_error( $response ) ) {
		return array();
	}

	$body = wp_remote_retrieve_body( $response );
	$data = json_decode( $body, true );

	if ( ! empty( $data['checksums'] ) && is_array( $data['checksums'] ) ) {
		set_transient( $transient_key, $data['checksums'], 7 * DAY_IN_SECONDS );
		return $data['checksums'];
	}

	return array();
}

/**
 * Verify a single core file against official checksums
 */
function hkymalvexa_verify_core_file( $relative_path, $full_path, $checksums ) {
	$norm_path = str_replace( '\\', '/', ltrim( $relative_path, '/\\' ) );

	if ( ! isset( $checksums[ $norm_path ] ) ) {
		// If file is inside wp-admin or wp-includes but NOT in official checksums, it's an extraneous rogue file!
		if ( strpos( $norm_path, 'wp-admin/' ) === 0 || strpos( $norm_path, 'wp-includes/' ) === 0 ) {
			if ( strpos( $norm_path, 'wp-content/' ) === false && substr( $norm_path, -4 ) === '.php' ) {
				return array(
					'status'      => 'rogue_file',
					'severity'    => 'critical',
					'confidence'  => 95,
					'description' => "Extraneous unknown PHP file found inside official WordPress core directory ({$norm_path}). Official releases do not contain this file.",
					'action'      => 'quarantine',
				);
			}
		}
		return null;
	}

	if ( ! file_exists( $full_path ) ) {
		return array(
			'status'      => 'missing',
			'severity'    => 'medium',
			'confidence'  => 90,
			'description' => "Official core file is missing: {$norm_path}.",
			'action'      => 'restore_core',
		);
	}

	$actual_md5 = md5_file( $full_path );
	if ( $actual_md5 !== $checksums[ $norm_path ] ) {
		return array(
			'status'      => 'modified',
			'severity'    => 'critical',
			'confidence'  => 98,
			'description' => "Core file tampering detected! The file ({$norm_path}) has been altered and differs from the official WordPress release hash.",
			'action'      => 'restore_core',
		);
	}

	return array( 'status' => 'clean' );
}

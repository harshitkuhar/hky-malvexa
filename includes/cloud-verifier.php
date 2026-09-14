<?php
/**
 * SiteCure Cloud-Assisted Token Verification Client (Option B)
 * Procedural client enforcing domain quota with Developer Master Key bypass
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get or generate unique installation identifier
 *
 * @return string
 */
function sitecure_get_install_id() {
	$install_id = get_option( 'sitecure_install_id', '' );
	if ( empty( $install_id ) ) {
		$install_id = get_option( 'sitecure_install_id', '' );
	}

	if ( empty( $install_id ) ) {
		$seed = home_url() . '|' . ( defined( 'AUTH_KEY' ) ? AUTH_KEY : wp_salt() ) . '|' . microtime();
		$install_id = 'sc_' . substr( hash( 'sha256', $seed ), 0, 32 );
		update_option( 'sitecure_install_id', $install_id );
	}

	return $install_id;
}

/**
 * Get cloud verification microservice endpoint URL
 *
 * @return string
 */
function sitecure_get_cloud_endpoint() {
	// Official production Cloudflare Worker microservice endpoint
	return 'https://sitecure-verifier.hc-web1992.workers.dev';
}

/**
 * Normalize domain or site URL
 *
 * @param string $input
 * @return string
 */
function sitecure_normalize_domain( $input ) {
	if ( empty( $input ) ) {
		return '';
	}

	$clean = trim( strtolower( $input ) );
	$host  = parse_url( $clean, PHP_URL_HOST );
	if ( ! empty( $host ) ) {
		$clean = $host;
	} else {
		$clean = preg_replace( '#^https?://#i', '', $clean );
		$clean = trim( explode( '/', $clean )[0] );
		$clean = trim( explode( ':', $clean )[0] );
	}

	return preg_replace( '/^www\./i', '', $clean );
}

/**
 * Register a domain with the cloud microservice
 *
 * @param string $domain_or_url
 * @return true|WP_Error
 */
function sitecure_cloud_register_domain( $domain_or_url ) {
	$domain = sitecure_normalize_domain( $domain_or_url );
	if ( empty( $domain ) ) {
		return new WP_Error( 'invalid_domain', __( 'Invalid domain or site URL.', 'sitecure' ) );
	}

	// Developer Mode Bypass: Local or Master Key
	if ( function_exists( 'sitecure_is_dev_mode' ) && sitecure_is_dev_mode() ) {
		return true;
	}

	$endpoint = sitecure_get_cloud_endpoint() . '/api/register';
	$license  = get_option( 'sitecure_pro_license_key', '' );
	if ( empty( $license ) ) {
		$license = get_option( 'sitecure_pro_license_key', '' );
	}

	$payload = array(
		'action'         => 'register',
		'install_id'     => sitecure_get_install_id(),
		'domain'         => $domain,
		'license_key'    => $license,
		'plugin_version' => defined( 'SITECURE_VERSION' ) ? SITECURE_VERSION : '1.0.0',
	);

	$response = wp_remote_post(
		$endpoint,
		array(
			'timeout' => 5,
			'headers' => array( 'Content-Type' => 'application/json; charset=utf-8' ),
			'body'    => wp_json_encode( $payload ),
		)
	);

	// Graceful Offline Fallback: If cloud server is down or network unavailable, check local database quota
	if ( is_wp_error( $response ) ) {
		if ( function_exists( 'sitecure_can_add_site' ) && sitecure_can_add_site() ) {
			return true;
		}
		return new WP_Error( 'quota_reached', __( 'Free plan limit reached (1 site). Upgrade to SiteCure Pro to manage multiple websites.', 'sitecure' ) );
	}

	$code = wp_remote_retrieve_response_code( $response );
	$body = wp_remote_retrieve_body( $response );
	$data = json_decode( $body, true );

	if ( $code === 403 || ( isset( $data['authorized'] ) && ! $data['authorized'] ) ) {
		$msg = ! empty( $data['message'] ) ? $data['message'] : __( 'Free plan limit reached (1 active site). Upgrade to SiteCure Pro to add client websites.', 'sitecure' );
		return new WP_Error( 'quota_exceeded', $msg );
	}

	if ( $code === 200 && ! empty( $data['authorized'] ) ) {
		set_transient( 'sitecure_ver_' . md5( $domain ), true, 12 * HOUR_IN_SECONDS );
		return true;
	}

	// Fallback to local quota check
	if ( function_exists( 'sitecure_can_add_site' ) && sitecure_can_add_site() ) {
		return true;
	}

	return new WP_Error( 'quota_reached', __( 'Free plan limit reached (1 site). Upgrade to SiteCure Pro to manage multiple websites.', 'sitecure' ) );
}

/**
 * Verify if domain is authorized to scan
 *
 * @param string $domain_or_url
 * @return true|WP_Error
 */
function sitecure_cloud_verify_domain( $domain_or_url ) {
	if ( function_exists( 'sitecure_is_dev_mode' ) && sitecure_is_dev_mode() ) {
		return true;
	}

	$domain = sitecure_normalize_domain( $domain_or_url );
	if ( empty( $domain ) ) {
		return true;
	}

	// Check local cache transient
	$cache_key = 'sitecure_ver_' . md5( $domain );
	if ( get_transient( $cache_key ) ) {
		return true;
	}

	$endpoint = sitecure_get_cloud_endpoint() . '/api/verify';
	$license  = get_option( 'sitecure_pro_license_key', '' );
	if ( empty( $license ) ) {
		$license = get_option( 'sitecure_pro_license_key', '' );
	}

	$payload = array(
		'action'         => 'verify',
		'install_id'     => sitecure_get_install_id(),
		'domain'         => $domain,
		'license_key'    => $license,
		'plugin_version' => defined( 'SITECURE_VERSION' ) ? SITECURE_VERSION : '1.0.0',
	);

	$response = wp_remote_post(
		$endpoint,
		array(
			'timeout' => 5,
			'headers' => array( 'Content-Type' => 'application/json; charset=utf-8' ),
			'body'    => wp_json_encode( $payload ),
		)
	);

	// Fail-closed offline protection: If cloud is offline, only allow if this is the single primary local site
	if ( is_wp_error( $response ) ) {
		$home_domain = sitecure_normalize_domain( home_url() );
		if ( $domain === $home_domain || ( function_exists( 'sitecure_get_sites' ) && count( sitecure_get_sites() ) <= 1 ) ) {
			return true;
		}
		return new WP_Error( 'quota_verification_failed', __( 'Could not verify client domain with license server. Please verify your internet connection.', 'sitecure' ) );
	}

	$code = wp_remote_retrieve_response_code( $response );
	$body = wp_remote_retrieve_body( $response );
	$data = json_decode( $body, true );

	if ( $code === 403 || ( isset( $data['authorized'] ) && ! $data['authorized'] ) ) {
		$msg = ! empty( $data['message'] ) ? $data['message'] : __( 'Free plan limit reached (1 active site). Upgrade to SiteCure Pro to scan this domain.', 'sitecure' );
		return new WP_Error( 'quota_exceeded', $msg );
	}

	if ( $code === 200 && ! empty( $data['authorized'] ) ) {
		set_transient( $cache_key, true, 12 * HOUR_IN_SECONDS );
		return true;
	}

	return new WP_Error( 'quota_exceeded', __( 'Domain is not authorized for scanning. Upgrade to SiteCure Pro to manage multiple websites.', 'sitecure' ) );
}

/**
 * Release a domain slot on the cloud microservice (called when site is deleted)
 *
 * @param string $domain_or_url
 * @return bool
 */
function sitecure_cloud_release_domain( $domain_or_url ) {
	$domain = sitecure_normalize_domain( $domain_or_url );
	if ( ! empty( $domain ) ) {
		delete_transient( 'sitecure_ver_' . md5( $domain ) );
	}

	if ( function_exists( 'sitecure_is_dev_mode' ) && sitecure_is_dev_mode() ) {
		return true;
	}

	$endpoint = sitecure_get_cloud_endpoint() . '/api/release';
	$payload  = array(
		'action'     => 'release',
		'install_id' => sitecure_get_install_id(),
		'domain'     => $domain,
	);

	wp_remote_post(
		$endpoint,
		array(
			'timeout'  => 5,
			'headers'  => array( 'Content-Type' => 'application/json; charset=utf-8' ),
			'body'     => wp_json_encode( $payload ),
			'blocking' => false, // Non-blocking asynchronous request so UI remains instant
		)
	);

	return true;
}

/**
 * Check license validity with the cloud microservice
 *
 * @param string $license_key
 * @return array
 */
function sitecure_cloud_check_license( $license_key ) {
	$endpoint = sitecure_get_cloud_endpoint() . '/api/license';
	$payload  = array(
		'action'      => 'license_check',
		'license_key' => sanitize_text_field( $license_key ),
	);

	$response = wp_remote_post(
		$endpoint,
		array(
			'timeout' => 6,
			'headers' => array( 'Content-Type' => 'application/json; charset=utf-8' ),
			'body'    => wp_json_encode( $payload ),
		)
	);

	if ( is_wp_error( $response ) ) {
		return array(
			'valid'   => false,
			'message' => __( 'Could not connect to license server. Please verify your connection and try again.', 'sitecure' ),
		);
	}

	$body = wp_remote_retrieve_body( $response );
	$data = json_decode( $body, true );

	if ( is_array( $data ) && ! empty( $data['valid'] ) ) {
		set_transient( 'sitecure_pro_verified', true, 14 * DAY_IN_SECONDS );
		return $data;
	}

	delete_transient( 'sitecure_pro_verified' );
	return is_array( $data ) ? $data : array( 'valid' => false, 'message' => __( 'Invalid license server response.', 'sitecure' ) );
}

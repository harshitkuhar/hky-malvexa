<?php
/**
 * WP Doctor Procedural Post-Cleanup Verification Engine
 * Validates site availability, REST API responsiveness, and PHP error freedom
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpdoctor_verify_site_health( $site_url = '' ) {
	if ( empty( $site_url ) ) {
		$site_url = home_url();
	}

	$site_url = rtrim( $site_url, '/' );
	$results = array(
		'timestamp'    => current_time( 'mysql' ),
		'target_url'   => $site_url,
		'status'       => 'healthy',
		'checks'       => array(),
		'has_fatal'    => false,
		'response_ms'  => 0,
	);

	// 1. Check Homepage HTTP Status & Response Time
	$start_time = microtime( true );
	$home_response = wp_remote_get( $site_url, array( 'timeout' => 15, 'sslverify' => false ) );
	$elapsed_ms = round( ( microtime( true ) - $start_time ) * 1000 );
	$results['response_ms'] = $elapsed_ms;

	if ( is_wp_error( $home_response ) ) {
		$results['status'] = 'down';
		$results['checks']['homepage'] = array(
			'status'  => 'error',
			'message' => 'Failed to connect: ' . $home_response->get_error_message(),
		);
	} else {
		$code = wp_remote_retrieve_response_code( $home_response );
		$body = wp_remote_retrieve_body( $home_response );

		// Check for PHP Fatal Errors or White Screen of Death indicators
		$fatal_indicators = array( 'Fatal error:', 'Parse error:', 'Warning: require', 'Uncaught Error:' );
		$found_fatal = false;
		foreach ( $fatal_indicators as $fi ) {
			if ( stripos( $body, $fi ) !== false ) {
				$found_fatal = true;
				break;
			}
		}

		if ( $found_fatal ) {
			$results['status'] = 'degraded';
			$results['has_fatal'] = true;
			$results['checks']['homepage'] = array(
				'status'  => 'error',
				'code'    => $code,
				'message' => 'PHP fatal error detected on homepage output!',
			);
		} elseif ( $code === 200 ) {
			$results['checks']['homepage'] = array(
				'status'  => 'ok',
				'code'    => $code,
				'message' => "Homepage responded HTTP 200 OK in {$elapsed_ms}ms.",
			);
		} else {
			$results['status'] = 'warning';
			$results['checks']['homepage'] = array(
				'status'  => 'warning',
				'code'    => $code,
				'message' => "Homepage returned HTTP status {$code}.",
			);
		}
	}

	// 2. Check WordPress REST API Endpoint
	$rest_url = $site_url . '/wp-json/';
	$rest_response = wp_remote_get( $rest_url, array( 'timeout' => 10, 'sslverify' => false ) );
	if ( ! is_wp_error( $rest_response ) && wp_remote_retrieve_response_code( $rest_response ) === 200 ) {
		$results['checks']['rest_api'] = array(
			'status'  => 'ok',
			'message' => 'WordPress REST API is accessible and responding.',
		);
	} else {
		$results['checks']['rest_api'] = array(
			'status'  => 'warning',
			'message' => 'WordPress REST API endpoint was not reachable.',
		);
	}

	// 3. Check Login Page accessibility
	$login_url = $site_url . '/wp-login.php';
	$login_response = wp_remote_get( $login_url, array( 'timeout' => 10, 'sslverify' => false ) );
	if ( ! is_wp_error( $login_response ) && wp_remote_retrieve_response_code( $login_response ) === 200 ) {
		$results['checks']['wp_login'] = array(
			'status'  => 'ok',
			'message' => 'WordPress Login screen (wp-login.php) is active and accessible.',
		);
	} else {
		$results['checks']['wp_login'] = array(
			'status'  => 'warning',
			'message' => 'WordPress Login screen returned non-200 response.',
		);
	}

	wpdoctor_log_audit( 1, 'verify_health', $site_url, "Verification completed. Status: {$results['status']}." );

	return $results;
}

<?php
/**
 * WP Doctor Procedural Persistence Forensics Analyzer
 * Inspects MU-plugins, Drop-in files, and WP-Cron events
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scan Must-Use Plugins and Drop-ins
 */
function wpdoctor_scan_dropins_and_mu( $wp_path = ABSPATH ) {
	$findings = array();

	$dropins = array(
		'db.php',
		'object-cache.php',
		'advanced-cache.php',
		'sunrise.php',
		'blog-deleted.php',
		'blog-inactive.php',
		'blog-suspended.php',
	);

	$wp_content_dir = rtrim( $wp_path, '/\\' ) . '/wp-content';
	foreach ( $dropins as $dropin ) {
		$file = $wp_content_dir . '/' . $dropin;
		if ( file_exists( $file ) ) {
			$detected = wpdoctor_scan_file_malware( $file, 'wp-content/' . $dropin );
			if ( ! empty( $detected ) ) {
				$findings = array_merge( $findings, $detected );
			} else {
				$findings[] = array(
					'severity'           => 'low',
					'classification'     => 'informational',
					'confidence'         => 60,
					'category'           => 'persistence_dropin',
					'file_path'          => 'wp-content/' . $dropin,
					'line_number'        => 1,
					'evidence'           => 'Drop-in file present: ' . $dropin,
					'description'        => "WordPress Drop-in detected ({$dropin}). Please verify this drop-in is intentionally installed by your caching or database plugin.",
					'recommended_action' => 'review',
				);
			}
		}
	}

	// MU-Plugins
	$mu_dir = $wp_content_dir . '/mu-plugins';
	if ( is_dir( $mu_dir ) ) {
		$files = glob( $mu_dir . '/*.php' );
		if ( ! empty( $files ) ) {
			foreach ( $files as $file ) {
				$rel = 'wp-content/mu-plugins/' . basename( $file );
				$detected = wpdoctor_scan_file_malware( $file, $rel );
				if ( ! empty( $detected ) ) {
					$findings = array_merge( $findings, $detected );
				}
			}
		}
	}

	return $findings;
}

/**
 * Inspect WP-Cron for suspicious hooks or malicious callbacks
 */
function wpdoctor_scan_cron_jobs( $site_id = 0 ) {
	$findings = array();

	$crons = array();
	if ( ! empty( $site_id ) && function_exists( 'wpdoctor_get_target_db' ) ) {
		$db = wpdoctor_get_target_db( $site_id );
		$options_table = $db->prefix . 'options';
		$cron_opt = $db->get_var( "SELECT option_value FROM `{$options_table}` WHERE option_name = 'cron' LIMIT 1" );
		if ( ! empty( $cron_opt ) ) {
			$crons = maybe_unserialize( $cron_opt );
		}
	}

	if ( empty( $crons ) || ! is_array( $crons ) ) {
		$crons = _get_cron_array();
	}

	if ( empty( $crons ) || ! is_array( $crons ) ) {
		return $findings;
	}

	$suspicious_keywords = array( 'eval', 'assert', 'base64', 'shell', 'exec', 'system', 'passthru', 'curl_exec', 'file_put_contents' );

	foreach ( $crons as $timestamp => $hooks ) {
		if ( ! is_array( $hooks ) ) {
			continue;
		}
		foreach ( $hooks as $hook_name => $hook_events ) {
			foreach ( $suspicious_keywords as $kw ) {
				if ( stripos( $hook_name, $kw ) !== false ) {
					$findings[] = array(
						'severity'           => 'high',
						'classification'     => 'suspicious',
						'confidence'         => 85,
						'category'           => 'persistence_cron',
						'file_path'          => 'database:wp_options[cron]',
						'line_number'        => 0,
						'evidence'           => 'Scheduled hook name: ' . esc_html( $hook_name ),
						'description'        => "Suspicious scheduled cron job hook ({$hook_name}) contains dangerous function keyword.",
						'recommended_action' => 'review',
					);
				}
			}
		}
	}

	return $findings;
}

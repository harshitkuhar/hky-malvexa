<?php
/**
 * WP Doctor Procedural Configuration Forensics Analyzer
 * Inspects wp-config.php, .htaccess, .user.ini, and php.ini for stealth hooks and tampering
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpdoctor_analyze_config_file( $full_path, $relative_path ) {
	$findings = array();
	$filename = basename( $full_path );

	if ( ! is_readable( $full_path ) ) {
		return $findings;
	}

	$content = @file_get_contents( $full_path );
	if ( empty( $content ) ) {
		return $findings;
	}

	// 1. wp-config.php analysis
	if ( $filename === 'wp-config.php' ) {
		if ( preg_match( '/(?:include|require|require_once|include_once)\s*\(?[\'"](?:https?:|\/\/|\/tmp|\/dev)/i', $content ) ) {
			$findings[] = array(
				'severity'           => 'critical',
				'classification'     => 'malicious',
				'confidence'         => 98,
				'category'           => 'config_tampering',
				'file_path'          => $relative_path,
				'line_number'        => 1,
				'evidence'           => 'Remote or /tmp include found in wp-config.php',
				'description'        => 'wp-config.php includes external or temporary files! This is a classic persistent backdoor hook.',
				'recommended_action' => 'review',
			);
		}

		if ( preg_match( '/eval\s*\(\s*(?:base64_decode|gzinflate)/i', $content ) ) {
			$findings[] = array(
				'severity'           => 'critical',
				'classification'     => 'malicious',
				'confidence'         => 99,
				'category'           => 'config_tampering',
				'file_path'          => $relative_path,
				'line_number'        => 1,
				'evidence'           => 'Obfuscated eval payload embedded in wp-config.php',
				'description'        => 'Critical: Obfuscated PHP code injected directly into wp-config.php.',
				'recommended_action' => 'review',
			);
		}
	}

	// 2. .htaccess / .user.ini auto-prepend backdoors
	if ( in_array( $filename, array( '.htaccess', '.user.ini', 'php.ini' ), true ) ) {
		if ( preg_match( '/auto_prepend_file\s*=\s*[\'"]?([^\r\n\'"]+)/i', $content, $m ) ) {
			$findings[] = array(
				'severity'           => 'critical',
				'classification'     => 'malicious',
				'confidence'         => 95,
				'category'           => 'stealth_prepend',
				'file_path'          => $relative_path,
				'line_number'        => 1,
				'evidence'           => $m[0],
				'description'        => 'Dangerous auto_prepend_file directive detected! Forces PHP to execute a script before every page load on the website.',
				'recommended_action' => 'quarantine',
			);
		}

		// Malicious spam redirects in .htaccess
		if ( $filename === '.htaccess' && preg_match( '/RewriteRule.*?(?:viagra|cialis|casino|poker|slot88|payday)/i', $content, $m ) ) {
			$findings[] = array(
				'severity'           => 'critical',
				'classification'     => 'malicious',
				'confidence'         => 95,
				'category'           => 'spam_redirect',
				'file_path'          => $relative_path,
				'line_number'        => 1,
				'evidence'           => $m[0],
				'description'        => 'Malicious spam/SEO redirect rules detected in .htaccess file.',
				'recommended_action' => 'review',
			);
		}
	}

	return $findings;
}

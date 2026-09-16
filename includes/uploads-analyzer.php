<?php
/**
 * HKY MalVexa Procedural Uploads Directory Analyzer
 * Detects rogue executables, disguised extensions, and unauthorized .htaccess in wp-content/uploads/
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function hkymalvexa_analyze_upload_file( $full_path, $relative_path ) {
	$findings = array();

	$full_path = str_replace( '\\', '/', $full_path );
	$norm_path = str_replace( '\\', '/', $relative_path );
	if ( strpos( $norm_path, 'wp-content/uploads/' ) === false ) {
		return $findings;
	}

	$filename = basename( $norm_path );

	// 1. Any PHP / executable script in uploads
	$dangerous_exts = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'cgi', 'pl', 'py', 'sh' );
	$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

	if ( in_array( $ext, $dangerous_exts, true ) ) {
		$findings[] = array(
			'severity'           => 'critical',
			'classification'     => 'malicious',
			'confidence'         => 99,
			'category'           => 'uploads_executable',
			'file_path'          => $relative_path,
			'line_number'        => 1,
			'evidence'           => "Executable file found in uploads: " . $filename,
			'description'        => 'PHP/executable script found directly in the uploads directory! Legitimate uploads should never contain executable PHP scripts.',
			'recommended_action' => 'quarantine',
		);
	}

	// 2. Double extensions
	if ( preg_match( '/\.(?:php\d?|phtml)\.[a-zA-Z0-9]+$/i', $filename ) || preg_match( '/\.[a-zA-Z0-9]+\.(?:php\d?|phtml)$/i', $filename ) ) {
		$findings[] = array(
			'severity'           => 'critical',
			'classification'     => 'malicious',
			'confidence'         => 98,
			'category'           => 'disguised_extension',
			'file_path'          => $relative_path,
			'line_number'        => 1,
			'evidence'           => "Disguised double-extension filename: " . $filename,
			'description'        => 'File with double-extension detected in uploads directory designed to trick web servers or bypass upload validations.',
			'recommended_action' => 'quarantine',
		);
	}

	// 3. Rogue .htaccess in uploads
	if ( $filename === '.htaccess' ) {
		$content = @file_get_contents( $full_path );
		if ( preg_match( '/(?:SetHandler|AddType|AddHandler).*?(?:php|x-httpd-php)/i', $content ) ) {
			$findings[] = array(
				'severity'           => 'critical',
				'classification'     => 'malicious',
				'confidence'         => 95,
				'category'           => 'rogue_htaccess',
				'file_path'          => $relative_path,
				'line_number'        => 1,
				'evidence'           => substr( $content, 0, 200 ),
				'description'        => 'Rogue .htaccess in uploads directory configured to enable PHP script execution!',
				'recommended_action' => 'quarantine',
			);
		}
	}

	// 4. PHP code hidden inside image/media/text files in uploads
	$media_exts = array( 'jpg', 'jpeg', 'png', 'gif', 'ico', 'svg', 'webp', 'txt', 'pdf', 'zip' );
	if ( in_array( $ext, $media_exts, true ) && @filesize( $full_path ) < 2 * 1024 * 1024 ) {
		$content = @file_get_contents( $full_path );
		if ( ! empty( $content ) && preg_match( '/<\?(?:php|=)/i', $content ) ) {
			$findings[] = array(
				'severity'           => 'critical',
				'classification'     => 'malicious',
				'confidence'         => 98,
				'category'           => 'embedded_php_media',
				'file_path'          => $relative_path,
				'line_number'        => 1,
				'evidence'           => 'Embedded executable PHP tag found inside static media file: ' . $filename,
				'description'        => 'Executable PHP code found inside a non-PHP media/text file in uploads! This is a stealth webshell dropper.',
				'recommended_action' => 'quarantine',
			);
		}
	}

	return $findings;
}

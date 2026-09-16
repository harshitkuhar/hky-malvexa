<?php
/**
 * HKY MalVexa Procedural File Classifier
 * Classifies files as CORE, PLUGIN, THEME, UPLOAD, CONFIG, CUSTOM or UNKNOWN
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function hkymalvexa_classify_file( $relative_path ) {
	$norm_path = str_replace( '\\', '/', ltrim( $relative_path, '/\\' ) );

	// Config files
	$config_names = array( 'wp-config.php', '.htaccess', '.user.ini', 'php.ini', 'web.config' );
	if ( in_array( basename( $norm_path ), $config_names, true ) ) {
		return 'CONFIG';
	}

	// Core folders
	if ( strpos( $norm_path, 'wp-admin/' ) === 0 || strpos( $norm_path, 'wp-includes/' ) === 0 ) {
		return 'CORE';
	}

	// Root core files
	$root_core_files = array(
		'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
		'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
		'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'
	);
	if ( in_array( $norm_path, $root_core_files, true ) ) {
		return 'CORE';
	}

	// Uploads
	if ( strpos( $norm_path, 'wp-content/uploads/' ) === 0 ) {
		return 'UPLOAD';
	}

	// Plugins and MU-Plugins
	if ( strpos( $norm_path, 'wp-content/plugins/' ) === 0 || strpos( $norm_path, 'wp-content/mu-plugins/' ) === 0 ) {
		return 'PLUGIN';
	}

	// Themes
	if ( strpos( $norm_path, 'wp-content/themes/' ) === 0 ) {
		return 'THEME';
	}

	// Other wp-content items
	if ( strpos( $norm_path, 'wp-content/' ) === 0 ) {
		return 'CUSTOM';
	}

	return 'UNKNOWN';
}

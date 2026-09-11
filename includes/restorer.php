<?php
/**
 * SiteCure Procedural Core File Restorer
 * Repairs altered or missing core files directly from official WordPress.org repositories
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function sitecure_repair_core_file( $relative_path, $version = '', $site_id = 0 ) {
	if ( empty( $version ) ) {
		global $wp_version;
		$version = $wp_version;
	}

	$norm_path = str_replace( '\\', '/', ltrim( $relative_path, '/\\' ) );
	$site_root = ( ! empty( $site_id ) && function_exists( 'sitecure_get_site_root' ) ) ? sitecure_get_site_root( $site_id ) : ABSPATH;
	$full_path = rtrim( str_replace( '\\', '/', $site_root ), '/' ) . '/' . $norm_path;

	// Create safety backup on client server first
	if ( file_exists( $full_path ) ) {
		$backup_dir = function_exists( 'sitecure_get_site_quarantine_dir' ) ? sitecure_get_site_quarantine_dir( $site_id, 'backups' ) : ABSPATH . 'wp-content/uploads/sitecure-quarantine/backups';
		@copy( $full_path, $backup_dir . '/' . sanitize_file_name( basename( $norm_path ) ) . '.' . time() . '.bak' );
	}

	// Download official file from WordPress SVN / GitHub official mirror
	$source_url = "https://core.svn.wordpress.org/tags/{$version}/" . $norm_path;
	$response = wp_remote_get( $source_url, array( 'timeout' => 20 ) );

	if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
		$fallback_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$version}/" . $norm_path;
		$response = wp_remote_get( $fallback_url, array( 'timeout' => 20 ) );
	}

	if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
		return new WP_Error( 'download_failed', 'Could not download official core file from WordPress.org repository.' );
	}

	$clean_content = wp_remote_retrieve_body( $response );
	if ( empty( $clean_content ) ) {
		return new WP_Error( 'empty_content', 'Downloaded official content is empty.' );
	}

	$dest_dir = dirname( $full_path );
	if ( ! is_dir( $dest_dir ) ) {
		wp_mkdir_p( $dest_dir );
	}

	if ( false === @file_put_contents( $full_path, $clean_content ) ) {
		return new WP_Error( 'write_failed', 'Could not write repaired core file to disk.' );
	}

	sitecure_log_audit( $site_id, 'repair_core_file', $norm_path, "Restored official WordPress core file from version {$version}." );

	return array(
		'success'   => true,
		'file_path' => $norm_path,
		'version'   => $version,
	);
}

<?php
/**
 * HKY MalVexa Procedural Core File Restorer
 * Repairs altered or missing core files directly from official WordPress.org repositories
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function hkymalvexa_repair_core_file( $relative_path, $version = '', $site_id = 0 ) {
	if ( empty( $version ) ) {
		global $wp_version;
		$version = $wp_version;
	}

	// 1. Sanitize and normalize input path
	$raw_path = wp_unslash( $relative_path );
	if ( empty( $raw_path ) ) {
		return new WP_Error( 'empty_path', __( 'No file path provided for core repair.', 'hky-malvexa' ) );
	}

	// Reject null bytes, backslashes, and path traversal attempts
	if ( strpos( $raw_path, "\0" ) !== false || strpos( $raw_path, '..' ) !== false ) {
		return new WP_Error( 'invalid_path', __( 'Invalid or prohibited file path for core repair.', 'hky-malvexa' ) );
	}

	$norm_path = str_replace( '\\', '/', ltrim( $raw_path, '/\\' ) );

	// 2. Reject any configuration files or web server rules
	$prohibited_files = array( 'wp-config.php', '.htaccess', '.user.ini', 'php.ini', 'web.config' );
	if ( in_array( strtolower( basename( $norm_path ) ), $prohibited_files, true ) ) {
		return new WP_Error( 'protected_file', __( 'Configuration files cannot be overwritten via core repair.', 'hky-malvexa' ) );
	}

	// 3. Reject any paths inside wp-content (plugins, themes, uploads, etc.)
	if ( strpos( $norm_path, 'wp-content/' ) === 0 || strpos( $norm_path, 'wp-content' ) === 0 ) {
		return new WP_Error( 'content_dir_rejected', __( 'Core repair cannot modify files in wp-content directory.', 'hky-malvexa' ) );
	}

	// 4. Must be a recognized core file classification
	if ( function_exists( 'hkymalvexa_classify_file' ) && hkymalvexa_classify_file( $norm_path ) !== 'CORE' ) {
		return new WP_Error( 'not_core_file', __( 'The target file is not a recognized WordPress core file.', 'hky-malvexa' ) );
	}

	// 5. Must fail closed if official checksums cannot be verified (Fix 1)
	if ( ! function_exists( 'hkymalvexa_get_core_checksums' ) ) {
		return new WP_Error(
			'checksum_unavailable',
			__( 'Official WordPress core checksums could not be verified. Core repair has been stopped.', 'hky-malvexa' )
		);
	}

	$checksums = hkymalvexa_get_core_checksums( $version );
	if ( empty( $checksums ) || ! is_array( $checksums ) ) {
		return new WP_Error(
			'checksum_unavailable',
			__( 'Official WordPress core checksums could not be verified. Core repair has been stopped.', 'hky-malvexa' )
		);
	}

	if ( ! isset( $checksums[ $norm_path ] ) ) {
		return new WP_Error(
			'not_official_core',
			__( 'The target file is not listed in the official WordPress release checksums.', 'hky-malvexa' )
		);
	}

	// 6. Resolve absolute path and enforce strict containment inside ABSPATH (Fix 2)
	$site_root = rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
	$full_path = $site_root . '/' . $norm_path;

	if ( strpos( $full_path, $site_root . '/' ) !== 0 ) {
		return new WP_Error( 'path_escape', __( 'Path escape detected.', 'hky-malvexa' ) );
	}

	// Reject symbolic links explicitly to prevent symlink escape
	if ( is_link( $full_path ) ) {
		return new WP_Error(
			'symlink_rejected',
			__( 'Core repair cannot modify a symbolic link.', 'hky-malvexa' )
		);
	}

	// Validate target directory and canonical path
	$dest_dir = dirname( $full_path );
	if ( is_link( $dest_dir ) ) {
		return new WP_Error(
			'symlink_rejected',
			__( 'Core repair cannot modify files inside a symbolic link directory.', 'hky-malvexa' )
		);
	}

	if ( file_exists( $dest_dir ) ) {
		$real_dest_dir = str_replace( '\\', '/', realpath( $dest_dir ) );
		if ( $real_dest_dir !== $site_root && strpos( $real_dest_dir, $site_root . '/' ) !== 0 ) {
			return new WP_Error( 'symlink_escape', __( 'Directory resolves outside of WordPress root.', 'hky-malvexa' ) );
		}
	}

	if ( file_exists( $full_path ) ) {
		$real_full_path = str_replace( '\\', '/', realpath( $full_path ) );
		if ( strpos( $real_full_path, $site_root . '/' ) !== 0 ) {
			return new WP_Error( 'symlink_escape', __( 'File resolves outside of WordPress root.', 'hky-malvexa' ) );
		}
	}

	// 7. Create safety backup in quarantine vault first
	if ( file_exists( $full_path ) ) {
		$upload_dir = wp_upload_dir();
		$backup_dir = function_exists( 'hkymalvexa_get_site_quarantine_dir' ) 
			? hkymalvexa_get_site_quarantine_dir( 1, 'backups' ) 
			: $upload_dir['basedir'] . '/hky-malvexa-quarantine/backups';
		@copy( $full_path, $backup_dir . '/' . sanitize_file_name( basename( $norm_path ) ) . '.' . time() . '.vault' );
	}

	// 8. Download official pristine file directly from WordPress.org official SVN repository
	$source_url = "https://core.svn.wordpress.org/tags/{$version}/" . $norm_path;
	$response   = wp_remote_get( $source_url, array( 'timeout' => 20 ) );

	if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
		return new WP_Error( 'download_failed', __( 'Could not download official core file from WordPress.org repository.', 'hky-malvexa' ) );
	}

	$clean_content = wp_remote_retrieve_body( $response );
	if ( empty( $clean_content ) ) {
		return new WP_Error( 'empty_content', __( 'Downloaded official content is empty.', 'hky-malvexa' ) );
	}

	// Verify downloaded content hash matches official checksum
	$expected_hash = $checksums[ $norm_path ];
	if ( md5( $clean_content ) !== $expected_hash ) {
		return new WP_Error(
			'checksum_mismatch',
			__( 'Downloaded file checksum does not match official WordPress release checksum.', 'hky-malvexa' )
		);
	}

	if ( ! is_dir( $dest_dir ) ) {
		wp_mkdir_p( $dest_dir );
	}

	// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Legitimate WordPress core file repair from official SVN repository.
	if ( false === @file_put_contents( $full_path, $clean_content ) ) {
		return new WP_Error( 'write_failed', __( 'Could not write repaired core file to disk.', 'hky-malvexa' ) );
	}

	if ( function_exists( 'hkymalvexa_log_audit' ) ) {
		hkymalvexa_log_audit( 1, 'repair_core_file', $norm_path, "Restored official WordPress core file from version {$version}." );
	}

	return array(
		'success'   => true,
		'file_path' => $norm_path,
		'version'   => $version,
	);
}

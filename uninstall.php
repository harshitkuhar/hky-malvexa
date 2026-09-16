<?php
/**
 * HKY MalVexa Plugin Uninstaller
 * Executed when the user clicks "Delete" on the Plugins page.
 * Completely purges all data, database tables, options, transients, and files from the host server.
 */

// If uninstall not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.NamingConventions.PrefixAllGlobals, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Plugin uninstaller drops custom plugin tables upon explicit deletion.

/**
 * Recursively delete a directory and all of its contents
 */
function hkymalvexa_uninstall_recursive_rmdir( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return;
	}

	global $wp_filesystem;
	if ( empty( $wp_filesystem ) ) {
		require_once ABSPATH . '/wp-admin/includes/file.php';
		WP_Filesystem();
	}

	if ( ! empty( $wp_filesystem ) ) {
		$wp_filesystem->delete( $dir, true );
		return;
	}

	$items = @scandir( $dir );
	if ( ! is_array( $items ) ) {
		return;
	}

	foreach ( $items as $item ) {
		if ( $item === '.' || $item === '..' ) {
			continue;
		}

		$path = $dir . DIRECTORY_SEPARATOR . $item;
		if ( is_dir( $path ) ) {
			hkymalvexa_uninstall_recursive_rmdir( $path );
		} else {
			wp_delete_file( $path );
		}
	}

	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	@rmdir( $dir );
}

/**
 * Purge all HKY MalVexa database tables, options, and filesystem data for current site
 */
function hkymalvexa_uninstall_purge_site_data() {
	global $wpdb;

	$host_root = rtrim( str_replace( '\\', '/', ABSPATH ), '/' );

	// 1. Wipe quarantine vault, backup files, and temporary files from the uploads directory
	$upload_dir = wp_upload_dir();
	if ( ! empty( $upload_dir['basedir'] ) ) {
		$host_quarantines = array(
			$upload_dir['basedir'] . '/hky-malvexa-quarantine',
			$upload_dir['basedir'] . '/hkymalvexa-quarantine',
		);
		foreach ( $host_quarantines as $hq ) {
			if ( is_dir( $hq ) ) {
				hkymalvexa_uninstall_recursive_rmdir( $hq );
			}
		}
	}
	$root_quarantines = array(
		$host_root . '/wp-content/uploads/hky-malvexa-quarantine',
		$host_root . '/wp-content/uploads/hkymalvexa-quarantine',
	);
	foreach ( $root_quarantines as $rq ) {
		if ( is_dir( $rq ) ) {
			hkymalvexa_uninstall_recursive_rmdir( $rq );
		}
	}

	// 2. Clear any registered scheduled cron tasks
	wp_clear_scheduled_hook( 'hkymalvexa_scheduled_scan' );

	// 3. Delete all options, settings, and transients from wp_options
	$wpdb->query(
		"DELETE FROM `{$wpdb->options}` 
		WHERE option_name LIKE 'hkymalvexa_%' 
		   OR option_name LIKE '_transient_hkymalvexa_%' 
		   OR option_name LIKE '_transient_timeout_hkymalvexa_%'"
	);

	// Multisite network sitemeta cleanup if table exists
	if ( ! empty( $wpdb->sitemeta ) ) {
		$wpdb->query(
			"DELETE FROM `{$wpdb->sitemeta}`
			WHERE meta_key LIKE 'hkymalvexa_%'
			   OR meta_key LIKE '_transient_hkymalvexa_%'
			   OR meta_key LIKE '_transient_timeout_hkymalvexa_%'"
		);
	}

	// 4. Drop all custom database tables
	$tables = array(
		$wpdb->prefix . 'hkymalvexa_sites',
		$wpdb->prefix . 'hkymalvexa_scans',
		$wpdb->prefix . 'hkymalvexa_findings',
		$wpdb->prefix . 'hkymalvexa_quarantine',
		$wpdb->prefix . 'hkymalvexa_audit_logs',
	);

	foreach ( $tables as $table ) {
		$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" );
	}

	// Dynamic fallback: Drop any remaining tables starting with prefix + hkymalvexa_
	$wildcard_tables = $wpdb->get_col( "SHOW TABLES LIKE '{$wpdb->prefix}hkymalvexa_%'" );
	if ( ! empty( $wildcard_tables ) ) {
		foreach ( $wildcard_tables as $tbl ) {
			$wpdb->query( "DROP TABLE IF EXISTS `{$tbl}`" );
		}
	}
}

// Execute uninstallation cleanup
if ( is_multisite() ) {
	$sites = get_sites();
	if ( ! empty( $sites ) ) {
		foreach ( $sites as $site ) {
			switch_to_blog( (int) $site->blog_id );
			hkymalvexa_uninstall_purge_site_data();
			restore_current_blog();
		}
	} else {
		hkymalvexa_uninstall_purge_site_data();
	}
} else {
	hkymalvexa_uninstall_purge_site_data();
}

<?php
/**
 * WP Doctor Plugin Uninstaller
 * Executed when the user clicks "Delete" on the Plugins page.
 * Completely purges all data, database tables, options, transients, and files from the host server.
 */

// If uninstall not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Recursively delete a directory and all of its contents
 */
function wpdoctor_uninstall_recursive_rmdir( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return;
	}

	$items = @scandir( $dir );
	if ( false === $items ) {
		return;
	}

	foreach ( $items as $item ) {
		if ( $item === '.' || $item === '..' ) {
			continue;
		}

		$path = $dir . DIRECTORY_SEPARATOR . $item;
		if ( is_dir( $path ) ) {
			wpdoctor_uninstall_recursive_rmdir( $path );
		} else {
			@unlink( $path );
		}
	}

	@rmdir( $dir );
}

/**
 * Purge all WP Doctor database tables, options, and filesystem data for current site
 */
function wpdoctor_uninstall_purge_site_data() {
	global $wpdb;

	$host_root = rtrim( str_replace( '\\', '/', ABSPATH ), '/' );

	// 1. Purge quarantine vaults from all client/external sites BEFORE dropping tables
	$table_sites = $wpdb->prefix . 'wpdoctor_sites';
	if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_sites}'" ) === $table_sites ) {
		$client_sites = $wpdb->get_results( "SELECT * FROM `{$table_sites}`" );
		if ( ! empty( $client_sites ) ) {
			foreach ( $client_sites as $cs ) {
				$site_root = '';
				if ( ! empty( $cs->wp_path ) && file_exists( $cs->wp_path ) ) {
					$site_root = $cs->wp_path;
				} elseif ( ! empty( $cs->wp_path ) && file_exists( dirname( ABSPATH ) . '/' . ltrim( $cs->wp_path, '/\\' ) ) ) {
					$site_root = dirname( ABSPATH ) . '/' . ltrim( $cs->wp_path, '/\\' );
				} else {
					$url_path = parse_url( $cs->url, PHP_URL_PATH );
					if ( ! empty( $url_path ) ) {
						$slug = trim( $url_path, '/' );
						if ( ! empty( $slug ) && is_dir( dirname( ABSPATH ) . '/' . $slug ) ) {
							$site_root = dirname( ABSPATH ) . '/' . $slug;
						}
					}
				}

				if ( ! empty( $site_root ) ) {
					$site_root = rtrim( str_replace( '\\', '/', $site_root ), '/' );
					// Remove the quarantine directories on the client site
					$client_quarantines = array(
						$site_root . '/wp-content/uploads/sitecure-quarantine',
						$site_root . '/wp-content/uploads/wp-doctor-quarantine',
					);
					foreach ( $client_quarantines as $cq ) {
						if ( is_dir( $cq ) ) {
							wpdoctor_uninstall_recursive_rmdir( $cq );
						}
					}
				}
			}
		}
	}

	// 2. Also wipe any quarantine vault, backup files, or temporary files from the host server
	$upload_dir = wp_upload_dir();
	if ( ! empty( $upload_dir['basedir'] ) ) {
		$host_quarantines = array(
			$upload_dir['basedir'] . '/sitecure-quarantine',
			$upload_dir['basedir'] . '/wp-doctor-quarantine',
		);
		foreach ( $host_quarantines as $hq ) {
			if ( is_dir( $hq ) ) {
				wpdoctor_uninstall_recursive_rmdir( $hq );
			}
		}
	}
	$root_quarantines = array(
		$host_root . '/wp-content/uploads/sitecure-quarantine',
		$host_root . '/wp-content/uploads/wp-doctor-quarantine',
	);
	foreach ( $root_quarantines as $rq ) {
		if ( is_dir( $rq ) ) {
			wpdoctor_uninstall_recursive_rmdir( $rq );
		}
	}

	// 3. Clear any registered scheduled cron tasks
	wp_clear_scheduled_hook( 'sitecure_scheduled_scan' );
	wp_clear_scheduled_hook( 'wpdoctor_scheduled_scan' );

	// 4. Delete all options, settings, and transients from wp_options
	$wpdb->query(
		"DELETE FROM `{$wpdb->options}` 
		WHERE option_name LIKE 'sitecure_%' 
		   OR option_name LIKE '_transient_sitecure_%' 
		   OR option_name LIKE '_transient_timeout_sitecure_%'
		   OR option_name LIKE 'wpdoctor_%' 
		   OR option_name LIKE '_transient_wpdoctor_%' 
		   OR option_name LIKE '_transient_timeout_wpdoctor_%'"
	);

	// Multisite network sitemeta cleanup if table exists
	if ( ! empty( $wpdb->sitemeta ) ) {
		$wpdb->query(
			"DELETE FROM `{$wpdb->sitemeta}`
			WHERE meta_key LIKE 'sitecure_%'
			   OR meta_key LIKE '_transient_sitecure_%'
			   OR meta_key LIKE '_transient_timeout_sitecure_%'
			   OR meta_key LIKE 'wpdoctor_%'
			   OR meta_key LIKE '_transient_wpdoctor_%'
			   OR meta_key LIKE '_transient_timeout_wpdoctor_%'"
		);
	}

	// 5. Drop all custom database tables
	$tables = array(
		$wpdb->prefix . 'wpdoctor_sites',
		$wpdb->prefix . 'wpdoctor_connections',
		$wpdb->prefix . 'wpdoctor_scans',
		$wpdb->prefix . 'wpdoctor_findings',
		$wpdb->prefix . 'wpdoctor_quarantine',
		$wpdb->prefix . 'wpdoctor_audit_logs',
		$wpdb->prefix . 'sitecure_sites',
		$wpdb->prefix . 'sitecure_connections',
		$wpdb->prefix . 'sitecure_scans',
		$wpdb->prefix . 'sitecure_findings',
		$wpdb->prefix . 'sitecure_quarantine',
		$wpdb->prefix . 'sitecure_audit_logs',
	);

	foreach ( $tables as $table ) {
		$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" );
	}

	// Dynamic fallback: Drop any remaining tables starting with prefix + sitecure_ or wpdoctor_
	$wildcard_tables = $wpdb->get_col( "SHOW TABLES LIKE '{$wpdb->prefix}sitecure_%'" );
	if ( ! empty( $wildcard_tables ) ) {
		foreach ( $wildcard_tables as $tbl ) {
			$wpdb->query( "DROP TABLE IF EXISTS `{$tbl}`" );
		}
	}
	$wildcard_tables_legacy = $wpdb->get_col( "SHOW TABLES LIKE '{$wpdb->prefix}wpdoctor_%'" );
	if ( ! empty( $wildcard_tables_legacy ) ) {
		foreach ( $wildcard_tables_legacy as $tbl ) {
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
			wpdoctor_uninstall_purge_site_data();
			restore_current_blog();
		}
	} else {
		wpdoctor_uninstall_purge_site_data();
	}
} else {
	wpdoctor_uninstall_purge_site_data();
}

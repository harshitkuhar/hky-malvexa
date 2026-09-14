<?php
/**
 * SiteCure Procedural Database Handler
 * Dedicated custom tables using $wpdb
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dedicated custom database tables for SiteCure scans, findings, quarantine, and audit logs.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get table name with prefix
 */
function sitecure_get_table( $name ) {
	global $wpdb;
	return $wpdb->prefix . 'sitecure_' . $name;
}

function sitecure_maybe_install_tables() {
	global $wpdb;
	$table_sites = sitecure_get_table( 'sites' );
	if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_sites'" ) !== $table_sites ) {
		sitecure_install_database_tables();
	} else {
		// Ensure current site always reflects SiteCure
		$wpdb->query( "UPDATE $table_sites SET name = 'SiteCure (Current Site)' WHERE access_mode = 'local'" );
	}
}
add_action( 'admin_init', 'sitecure_maybe_install_tables' );

/**
 * Install or upgrade custom tables
 */
function sitecure_install_database_tables() {
	global $wpdb;
	$charset_collate = $wpdb->get_charset_collate();

	if ( ! function_exists( 'dbDelta' ) && file_exists( ABSPATH . 'wp-admin/includes/upgrade.php' ) ) {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	}

	// 1. Sites Table
	$table_sites = sitecure_get_table( 'sites' );
	$sql_sites = "CREATE TABLE $table_sites (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		name varchar(191) NOT NULL,
		url varchar(255) NOT NULL,
		environment varchar(50) DEFAULT 'production',
		access_mode varchar(50) DEFAULT 'local',
		wp_path text DEFAULT NULL,
		last_scan datetime DEFAULT NULL,
		health_status varchar(50) DEFAULT 'healthy',
		notes text DEFAULT NULL,
		created_at datetime DEFAULT CURRENT_TIMESTAMP,
		updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY  (id)
	) $charset_collate;";
	dbDelta( $sql_sites );

	// Cleanup: Do NOT add or retain current host site in Managed Sites
	$wpdb->query( "DELETE FROM $table_sites WHERE access_mode = 'local'" );

	// 2. Connections Table (Encrypted Credentials)
	$table_connections = sitecure_get_table( 'connections' );
	$sql_connections = "CREATE TABLE $table_connections (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		site_id bigint(20) unsigned NOT NULL,
		connection_type varchar(50) NOT NULL,
		host varchar(255) DEFAULT NULL,
		port int(11) DEFAULT 22,
		username varchar(191) DEFAULT NULL,
		encrypted_password longtext DEFAULT NULL,
		encrypted_key longtext DEFAULT NULL,
		remote_path varchar(255) DEFAULT NULL,
		created_at datetime DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY  (id),
		KEY site_id (site_id)
	) $charset_collate;";
	dbDelta( $sql_connections );

	// 3. Scans Table
	$table_scans = sitecure_get_table( 'scans' );
	$sql_scans = "CREATE TABLE $table_scans (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		site_id bigint(20) unsigned NOT NULL,
		scan_type varchar(50) DEFAULT 'deep',
		status varchar(50) DEFAULT 'pending',
		total_files int(11) DEFAULT 0,
		scanned_files int(11) DEFAULT 0,
		findings_count int(11) DEFAULT 0,
		started_at datetime DEFAULT NULL,
		completed_at datetime DEFAULT NULL,
		error_message text DEFAULT NULL,
		summary longtext DEFAULT NULL,
		batch_offset int(11) DEFAULT 0,
		PRIMARY KEY  (id),
		KEY site_id (site_id)
	) $charset_collate;";
	dbDelta( $sql_scans );

	// 4. Findings Table
	$table_findings = sitecure_get_table( 'findings' );
	$sql_findings = "CREATE TABLE $table_findings (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		scan_id bigint(20) unsigned NOT NULL,
		site_id bigint(20) unsigned NOT NULL,
		severity varchar(20) DEFAULT 'medium',
		classification varchar(30) DEFAULT 'suspicious',
		confidence int(11) DEFAULT 80,
		category varchar(50) DEFAULT 'malware',
		file_path text NOT NULL,
		line_number int(11) DEFAULT 0,
		evidence longtext DEFAULT NULL,
		description text DEFAULT NULL,
		recommended_action varchar(50) DEFAULT 'quarantine',
		status varchar(30) DEFAULT 'new',
		created_at datetime DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY  (id),
		KEY scan_id (scan_id),
		KEY site_id (site_id),
		KEY status (status)
	) $charset_collate;";
	dbDelta( $sql_findings );

	// 5. Quarantine Table
	$table_quarantine = sitecure_get_table( 'quarantine' );
	$sql_quarantine = "CREATE TABLE $table_quarantine (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		finding_id bigint(20) unsigned DEFAULT NULL,
		site_id bigint(20) unsigned NOT NULL,
		original_path text NOT NULL,
		original_hash varchar(64) DEFAULT NULL,
		original_permissions varchar(10) DEFAULT NULL,
		quarantine_path text NOT NULL,
		quarantine_hash varchar(64) DEFAULT NULL,
		reason text DEFAULT NULL,
		status varchar(30) DEFAULT 'quarantined',
		created_at datetime DEFAULT CURRENT_TIMESTAMP,
		restored_at datetime DEFAULT NULL,
		PRIMARY KEY  (id),
		KEY site_id (site_id)
	) $charset_collate;";
	dbDelta( $sql_quarantine );

	// 6. Audit Logs Table
	$table_audit = sitecure_get_table( 'audit_logs' );
	$sql_audit = "CREATE TABLE $table_audit (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		site_id bigint(20) unsigned DEFAULT 0,
		user_id bigint(20) unsigned DEFAULT 0,
		action varchar(100) NOT NULL,
		target_item text DEFAULT NULL,
		details longtext DEFAULT NULL,
		ip_address varchar(45) DEFAULT NULL,
		created_at datetime DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY  (id)
	) $charset_collate;";
	dbDelta( $sql_audit );
}

/**
 * Get protected quarantine or backup directory on the target site's own server
 * Ensures backups and vaults are created directly on client's server
 *
 * @param int $site_id
 * @param string $subdir Optional subdirectory ('cleaned_backups', 'vault', 'backups')
 * @return string Full filesystem path to the directory on the client site
 */
function sitecure_get_site_quarantine_dir( $site_id = 0, $subdir = '' ) {
	if ( ! empty( $site_id ) && (int) $site_id > 0 ) {
		$site_root = sitecure_get_site_root( $site_id );
	} else {
		// If no site_id, check if local site is registered before touching host uploads
		global $wpdb;
		$table_sites = sitecure_get_table( 'sites' );
		$has_local = $wpdb->get_var( "SELECT id FROM $table_sites WHERE access_mode = 'local' LIMIT 1" );
		if ( $has_local ) {
			$site_root = ABSPATH;
		} else {
			return '';
		}
	}

	$site_root = rtrim( str_replace( '\\', '/', $site_root ), '/' );
	if ( empty( $site_root ) ) {
		return '';
	}

	$quarantine_dir = $site_root . '/wp-content/uploads/sitecure-quarantine';

	if ( ! is_dir( $quarantine_dir ) ) {
		wp_mkdir_p( $quarantine_dir );
	}

	// Write .htaccess to prevent script execution completely
	$htaccess_file = $quarantine_dir . '/.htaccess';
	if ( ! file_exists( $htaccess_file ) ) {
		$htaccess_content = "# SiteCure Secure Storage Vault\n" .
			"Order Deny,Allow\n" .
			"Deny from all\n" .
			"<FilesMatch \".*\">\n" .
			"    Order Deny,Allow\n" .
			"    Deny from all\n" .
			"</FilesMatch>\n" .
			"<IfModule mod_php7.c>\n" .
			"    php_flag engine off\n" .
			"</IfModule>\n" .
			"<IfModule mod_php8.c>\n" .
			"    php_flag engine off\n" .
			"</IfModule>\n";
		@file_put_contents( $htaccess_file, $htaccess_content );
	}

	$index_file = $quarantine_dir . '/index.php';
	if ( ! file_exists( $index_file ) ) {
		@file_put_contents( $index_file, "<?php // Silence is golden." );
	}

	if ( ! empty( $subdir ) ) {
		$target_sub = $quarantine_dir . '/' . trim( str_replace( '\\', '/', $subdir ), '/' );
		if ( ! is_dir( $target_sub ) ) {
			wp_mkdir_p( $target_sub );
		}
		$sub_index = $target_sub . '/index.php';
		if ( ! file_exists( $sub_index ) ) {
			@file_put_contents( $sub_index, "<?php // Silence is golden." );
		}
		return $target_sub;
	}

	return $quarantine_dir;
}

/**
 * Initialize isolated quarantine storage directory
 */
function sitecure_init_quarantine_storage( $site_id = 0 ) {
	return sitecure_get_site_quarantine_dir( $site_id );
}

/**
 * Check if Pro / Multi-site tier is active
 * Verified strictly through server-side Cloudflare Worker verification
 *
 * @return bool
 */
function sitecure_is_dev_mode() {
	// Check saved license key and verified status from Cloudflare microservice
	$license = get_option( 'sitecure_pro_license_key', '' );
	if ( ! empty( $license ) ) {
		if ( get_transient( 'sitecure_pro_verified' ) ) {
			return true;
		}
	}

	return false;
}

/**
 * Get allowed site quota for current tier
 *
 * @return int 1 for Free tier, 9999 for Developer / Pro
 */
function sitecure_get_site_quota() {
	if ( sitecure_is_dev_mode() ) {
		return 9999;
	}
	return 1;
}

/**
 * Check if another site can be added within the quota
 *
 * @return bool
 */
function sitecure_can_add_site() {
	$sites = sitecure_get_sites();
	return count( $sites ) < sitecure_get_site_quota();
}

/**
 * Register current hosted site with 1-click
 *
 * @return int|WP_Error Site ID or error
 */
function sitecure_register_local_site() {
	global $wpdb;
	$table = sitecure_get_table( 'sites' );

	// Check if already registered
	$existing = $wpdb->get_row( "SELECT * FROM $table WHERE access_mode = 'local' LIMIT 1" );
	if ( $existing ) {
		return (int) $existing->id;
	}

	if ( ! sitecure_can_add_site() ) {
		return new WP_Error( 'quota_reached', 'Free plan limit reached (1 site). Upgrade to Pro to manage multiple websites.' );
	}

	// Option B Cloud Verification Check
	if ( function_exists( 'sitecure_cloud_register_domain' ) ) {
		$cloud_check = sitecure_cloud_register_domain( home_url() );
		if ( is_wp_error( $cloud_check ) ) {
			return $cloud_check;
		}
	}

	$name = 'SiteCure';

	$wpdb->insert(
		$table,
		array(
			'name'          => 'SiteCure (Current Site)',
			'url'           => home_url(),
			'environment'   => 'production',
			'access_mode'   => 'local',
			'wp_path'       => ABSPATH,
			'health_status' => 'healthy',
			'created_at'    => current_time( 'mysql' ),
		)
	);

	$site_id = (int) $wpdb->insert_id;
	sitecure_log_audit( $site_id, 'register_site', 'local', "Registered hosted site '{$name}' as Site #{$site_id}" );

	return $site_id;
}

/**
 * Delete a managed site and its associated scan records
 *
 * @param int $site_id
 * @return bool
 */
function sitecure_delete_site( $site_id ) {
	global $wpdb;
	$site_id = (int) $site_id;
	if ( $site_id <= 0 ) {
		return false;
	}

	$table_sites      = sitecure_get_table( 'sites' );
	$table_scans      = sitecure_get_table( 'scans' );
	$table_findings   = sitecure_get_table( 'findings' );
	$table_quarantine = sitecure_get_table( 'quarantine' );
	$table_audit      = sitecure_get_table( 'audit_logs' );

	$site = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_sites WHERE id = %d", $site_id ) );
	if ( ! $site ) {
		return false;
	}

	// Release domain quota slot in Cloud Verification Microservice (Option B)
	if ( function_exists( 'sitecure_cloud_release_domain' ) && ! empty( $site->url ) ) {
		sitecure_cloud_release_domain( $site->url );
	}

	// Delete from tables
	$wpdb->delete( $table_sites, array( 'id' => $site_id ) );
	$wpdb->delete( $table_scans, array( 'site_id' => $site_id ) );
	$wpdb->delete( $table_findings, array( 'site_id' => $site_id ) );
	$wpdb->delete( $table_quarantine, array( 'site_id' => $site_id ) );
	$wpdb->delete( $table_audit, array( 'site_id' => $site_id ) );

	return true;
}

/**
 * Log an audit event
 */
function sitecure_log_audit( $site_id, $action, $target, $details ) {
	global $wpdb;
	$table_audit = sitecure_get_table( 'audit_logs' );
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

	$wpdb->insert(
		$table_audit,
		array(
			'site_id'     => (int) $site_id,
			'user_id'     => get_current_user_id(),
			'action'      => sanitize_text_field( $action ),
			'target_item' => sanitize_text_field( $target ),
			'details'     => sanitize_textarea_field( $details ),
			'ip_address'  => $ip,
			'created_at'  => current_time( 'mysql' ),
		)
	);
}

/**
 * Get managed sites
 */
function sitecure_get_sites() {
	global $wpdb;
	$table = sitecure_get_table( 'sites' );
	$results = $wpdb->get_results( "SELECT * FROM $table ORDER BY id ASC" );
	if ( ! empty( $results ) ) {
		foreach ( $results as &$s ) {
			if ( isset( $s->access_mode ) && $s->access_mode === 'local' ) {
				$s->name = 'SiteCure (Current Site)';
			}
		}
	}
	return $results;
}

/**
 * Resolve filesystem root directory for any site
 */
function sitecure_get_site_root( $site_id ) {
	global $wpdb;
	$table_sites = sitecure_get_table( 'sites' );
	$site = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_sites WHERE id = %d", $site_id ) );
	$site_root = ABSPATH;

	if ( $site ) {
		if ( ! empty( $site->wp_path ) && file_exists( $site->wp_path ) ) {
			$site_root = $site->wp_path;
		} elseif ( ! empty( $site->wp_path ) && file_exists( dirname( ABSPATH ) . '/' . ltrim( $site->wp_path, '/\\' ) ) ) {
			$site_root = dirname( ABSPATH ) . '/' . ltrim( $site->wp_path, '/\\' );
		} else {
			$url_path = wp_parse_url( $site->url, PHP_URL_PATH );
			if ( ! empty( $url_path ) ) {
				$slug = trim( $url_path, '/' );
				if ( ! empty( $slug ) && is_dir( dirname( ABSPATH ) . '/' . $slug ) ) {
					$site_root = dirname( ABSPATH ) . '/' . $slug;
				}
			}
		}
	}
	return rtrim( str_replace( '\\', '/', $site_root ), '/' );
}

/**
 * Get dashboard overview statistics
 */
function sitecure_get_dashboard_stats() {
	global $wpdb;

	$table_sites = sitecure_get_table( 'sites' );
	$table_scans = sitecure_get_table( 'scans' );
	$table_findings = sitecure_get_table( 'findings' );
	$table_quarantine = sitecure_get_table( 'quarantine' );

	$total_sites = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_sites" );
	$healthy_sites = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_sites WHERE health_status = 'healthy'" );
	$warning_sites = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_sites WHERE health_status = 'warning'" );
	$compromised_sites = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_sites WHERE health_status = 'compromised'" );

	$total_scans = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_scans" );
	$active_findings = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_findings WHERE status = 'new'" );
	$critical_findings = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_findings WHERE status = 'new' AND severity = 'critical'" );
	$quarantined_files = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_quarantine WHERE status IN ('quarantined', 'cleaned')" );

	return array(
		'total_sites'        => $total_sites,
		'healthy_sites'      => $healthy_sites,
		'warning_sites'      => $warning_sites,
		'compromised_sites'  => $compromised_sites,
		'total_scans'        => $total_scans,
		'active_findings'    => $active_findings,
		'critical_findings'  => $critical_findings,
		'quarantined_files'  => $quarantined_files,
	);
}

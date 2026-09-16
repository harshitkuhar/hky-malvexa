<?php
/**
 * HKY MalVexa Procedural Database Handler
 * Dedicated custom tables using $wpdb
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dedicated custom database tables for HKY MalVexa scans, findings, quarantine, and audit logs.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get table name with prefix
 */
function hkymalvexa_get_table( $name ) {
	global $wpdb;
	return $wpdb->prefix . 'hkymalvexa_' . $name;
}

function hkymalvexa_maybe_install_tables() {
	global $wpdb;
	$table_sites = hkymalvexa_get_table( 'sites' );
	if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_sites'" ) !== $table_sites ) {
		hkymalvexa_install_database_tables();
	} else {
		// Ensure current site always reflects current site name and URL
		$site = $wpdb->get_row( "SELECT * FROM $table_sites WHERE access_mode = 'local' LIMIT 1" );
		if ( ! $site ) {
			$wpdb->insert(
				$table_sites,
				array(
					'name'          => get_bloginfo( 'name' ) ? get_bloginfo( 'name' ) : 'This WordPress Site',
					'url'           => home_url(),
					'environment'   => 'production',
					'access_mode'   => 'local',
					'wp_path'       => ABSPATH,
					'health_status' => 'healthy',
					'created_at'    => current_time( 'mysql' ),
				)
			);
		}
	}
}
add_action( 'admin_init', 'hkymalvexa_maybe_install_tables' );

/**
 * Install or upgrade custom tables
 */
function hkymalvexa_install_database_tables() {
	global $wpdb;
	$charset_collate = $wpdb->get_charset_collate();

	if ( ! function_exists( 'dbDelta' ) && file_exists( ABSPATH . 'wp-admin/includes/upgrade.php' ) ) {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	}

	// 1. Sites Table
	$table_sites = hkymalvexa_get_table( 'sites' );
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

	// Ensure local hosted site exists in Sites table
	$local_exists = $wpdb->get_var( "SELECT id FROM $table_sites WHERE access_mode = 'local' LIMIT 1" );
	if ( ! $local_exists ) {
		$wpdb->insert(
			$table_sites,
			array(
				'name'          => get_bloginfo( 'name' ) ? get_bloginfo( 'name' ) : 'This WordPress Site',
				'url'           => home_url(),
				'environment'   => 'production',
				'access_mode'   => 'local',
				'wp_path'       => ABSPATH,
				'health_status' => 'healthy',
				'created_at'    => current_time( 'mysql' ),
			)
		);
	}

	// 2. Scans Table
	$table_scans = hkymalvexa_get_table( 'scans' );
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
	$table_findings = hkymalvexa_get_table( 'findings' );
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
	$table_quarantine = hkymalvexa_get_table( 'quarantine' );
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
	$table_audit = hkymalvexa_get_table( 'audit_logs' );
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
function hkymalvexa_get_site_quarantine_dir( $site_id = 0, $subdir = '' ) {
	$upload = wp_upload_dir();
	$quarantine_dir = $upload['basedir'] . '/hky-malvexa-quarantine';

	if ( ! is_dir( $quarantine_dir ) ) {
		wp_mkdir_p( $quarantine_dir );
	}

	// Write .htaccess to prevent script execution completely
	$htaccess_file = $quarantine_dir . '/.htaccess';
	if ( ! file_exists( $htaccess_file ) ) {
		$htaccess_content = "# HKY MalVexa Secure Storage Vault\n" .
			"<IfModule mod_authz_core.c>\n" .
			"    Require all denied\n" .
			"</IfModule>\n" .
			"<IfModule !mod_authz_core.c>\n" .
			"    Order Deny,Allow\n" .
			"    Deny from all\n" .
			"</IfModule>\n" .
			"<FilesMatch \".*\">\n" .
			"    <IfModule mod_authz_core.c>\n" .
			"        Require all denied\n" .
			"    </IfModule>\n" .
			"    <IfModule !mod_authz_core.c>\n" .
			"        Order Deny,Allow\n" .
			"        Deny from all\n" .
			"    </IfModule>\n" .
			"</FilesMatch>\n" .
			"<IfModule mod_php7.c>\n" .
			"    php_flag engine off\n" .
			"</IfModule>\n" .
			"<IfModule mod_php8.c>\n" .
			"    php_flag engine off\n" .
			"</IfModule>\n";
		@file_put_contents( $htaccess_file, $htaccess_content );
	}

	// Write web.config for IIS servers
	$webconfig_file = $quarantine_dir . '/web.config';
	if ( ! file_exists( $webconfig_file ) ) {
		$webconfig_content = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" .
			"<configuration>\n" .
			"  <system.webServer>\n" .
			"    <authorization>\n" .
			"      <deny users=\"*\" />\n" .
			"    </authorization>\n" .
			"  </system.webServer>\n" .
			"</configuration>";
		@file_put_contents( $webconfig_file, $webconfig_content );
	}

	$index_file = $quarantine_dir . '/index.php';
	if ( ! file_exists( $index_file ) ) {
		@file_put_contents( $index_file, "<?php // Silence is golden.\nexit;\n" );
	}

	$html_file = $quarantine_dir . '/index.html';
	if ( ! file_exists( $html_file ) ) {
		@file_put_contents( $html_file, "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Directory access is forbidden.</h1></body></html>" );
	}

	if ( ! empty( $subdir ) ) {
		$target_sub = $quarantine_dir . '/' . trim( str_replace( '\\', '/', $subdir ), '/' );
		if ( ! is_dir( $target_sub ) ) {
			wp_mkdir_p( $target_sub );
		}
		$sub_index = $target_sub . '/index.php';
		if ( ! file_exists( $sub_index ) ) {
			@file_put_contents( $sub_index, "<?php // Silence is golden.\nexit;\n" );
		}
		$sub_html = $target_sub . '/index.html';
		if ( ! file_exists( $sub_html ) ) {
			@file_put_contents( $sub_html, "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Directory access is forbidden.</h1></body></html>" );
		}
		return $target_sub;
	}

	return $quarantine_dir;
}

/**
 * Initialize isolated quarantine storage directory
 */
function hkymalvexa_init_quarantine_storage( $site_id = 0 ) {
	return hkymalvexa_get_site_quarantine_dir( $site_id );
}


/**
 * Log an audit event
 */
function hkymalvexa_log_audit( $site_id, $action, $target, $details ) {
	global $wpdb;
	$table_audit = hkymalvexa_get_table( 'audit_logs' );
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
 * Get registered sites
 */
function hkymalvexa_get_sites() {
	global $wpdb;
	$table = hkymalvexa_get_table( 'sites' );
	$results = $wpdb->get_results( "SELECT * FROM $table ORDER BY id ASC" );
	if ( ! empty( $results ) ) {
		foreach ( $results as &$s ) {
			if ( isset( $s->access_mode ) && $s->access_mode === 'local' ) {
				$s->name = 'HKY MalVexa (Current Site)';
			}
		}
	}
	return $results;
}

/**
 * Resolve validated filesystem root directory for any site
 *
 * @param int|object $site_or_id
 * @return string
 */
function hkymalvexa_get_site_root( $site_or_id = null ) {
	return rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
}

/**
 * Helper to get the single local site ID
 *
 * @return int
 */
function hkymalvexa_get_current_site_id() {
	global $wpdb;
	$table_sites = hkymalvexa_get_table( 'sites' );
	$site_id     = (int) $wpdb->get_var( "SELECT id FROM $table_sites WHERE access_mode = 'local' LIMIT 1" );
	if ( ! $site_id ) {
		hkymalvexa_maybe_install_tables();
		$site_id = (int) $wpdb->get_var( "SELECT id FROM $table_sites WHERE access_mode = 'local' LIMIT 1" );
	}
	return $site_id > 0 ? $site_id : 1;
}

/**
 * Get dashboard overview statistics for the current WordPress site
 */
function hkymalvexa_get_dashboard_stats() {
	global $wpdb;

	$table_scans      = hkymalvexa_get_table( 'scans' );
	$table_findings   = hkymalvexa_get_table( 'findings' );
	$table_quarantine = hkymalvexa_get_table( 'quarantine' );

	$total_scans        = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_scans" );
	$active_findings    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_findings WHERE status = 'new'" );
	$critical_findings  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_findings WHERE status = 'new' AND severity = 'critical'" );
	$quarantined_files  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_quarantine WHERE status IN ('quarantined', 'cleaned')" );
	$last_scanned_files = (int) $wpdb->get_var( "SELECT total_files FROM $table_scans ORDER BY id DESC LIMIT 1" );
	$last_scan_time     = $wpdb->get_var( "SELECT completed_at FROM $table_scans WHERE status = 'completed' ORDER BY id DESC LIMIT 1" );

	$protection_status  = ( $active_findings > 0 ) ? 'threats_found' : 'protected';

	return array(
		'protection_status'  => $protection_status,
		'total_scans'        => $total_scans,
		'last_scanned_files' => $last_scanned_files,
		'last_scan_time'     => $last_scan_time,
		'active_findings'    => $active_findings,
		'critical_findings'  => $critical_findings,
		'quarantined_files'  => $quarantined_files,
	);
}

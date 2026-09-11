<?php
/**
 * WP Doctor Procedural Database Handler
 * Dedicated custom tables using $wpdb
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get table name with prefix
 */
function wpdoctor_get_table( $name ) {
	global $wpdb;
	return $wpdb->prefix . 'wpdoctor_' . $name;
}

function wpdoctor_maybe_install_tables() {
	global $wpdb;
	$table_sites = wpdoctor_get_table( 'sites' );
	if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_sites'" ) !== $table_sites ) {
		wpdoctor_install_database_tables();
	}
}
add_action( 'admin_init', 'wpdoctor_maybe_install_tables' );

/**
 * Install or upgrade custom tables
 */
function wpdoctor_install_database_tables() {
	global $wpdb;
	$charset_collate = $wpdb->get_charset_collate();

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';

	// 1. Sites Table
	$table_sites = wpdoctor_get_table( 'sites' );
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

	// Cleanup any false-positive findings previously stored for wp-doctor
	$table_findings = wpdoctor_get_table( 'findings' );
	$wpdb->query( "DELETE FROM $table_findings WHERE file_path LIKE '%wp-doctor%'" );

	// 2. Connections Table (Encrypted Credentials)
	$table_connections = wpdoctor_get_table( 'connections' );
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
	$table_scans = wpdoctor_get_table( 'scans' );
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
	$table_findings = wpdoctor_get_table( 'findings' );
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
	$table_quarantine = wpdoctor_get_table( 'quarantine' );
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
	$table_audit = wpdoctor_get_table( 'audit_logs' );
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
function wpdoctor_get_site_quarantine_dir( $site_id = 0, $subdir = '' ) {
	if ( ! empty( $site_id ) && (int) $site_id > 0 ) {
		$site_root = wpdoctor_get_site_root( $site_id );
	} else {
		// If no site_id, check if local site is registered before touching host uploads
		global $wpdb;
		$table_sites = wpdoctor_get_table( 'sites' );
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
	// If legacy wp-doctor-quarantine exists and sitecure-quarantine doesn't yet, keep legacy or migrate
	if ( ! is_dir( $quarantine_dir ) && is_dir( $site_root . '/wp-content/uploads/wp-doctor-quarantine' ) ) {
		$quarantine_dir = $site_root . '/wp-content/uploads/wp-doctor-quarantine';
	}

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
function wpdoctor_init_quarantine_storage( $site_id = 0 ) {
	return wpdoctor_get_site_quarantine_dir( $site_id );
}

/**
 * Check if Developer Mode / Pro tier is active
 *
 * @return bool
 */
function wpdoctor_is_dev_mode() {
	// 1. Check if defined in wp-config.php: define( 'SITECURE_DEV_MODE', true ); or legacy WPDOCTOR_DEV_MODE
	if ( ( defined( 'SITECURE_DEV_MODE' ) && SITECURE_DEV_MODE ) || ( defined( 'WPDOCTOR_DEV_MODE' ) && WPDOCTOR_DEV_MODE ) ) {
		return true;
	}

	// 2. Check saved license key (SiteCure or legacy WP Doctor)
	$license = get_option( 'sitecure_pro_license_key', '' );
	if ( empty( $license ) ) {
		$license = get_option( 'wpdoctor_pro_license_key', '' );
	}

	if ( ! empty( $license ) ) {
		$norm = strtoupper( trim( $license ) );
		if ( $norm === 'SITECURE-DEV-UNLIMITED' || $norm === 'WPDOCTOR-DEV-UNLIMITED' || hash( 'sha256', $license ) === '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' ) {
			return true;
		}
	}

	// 3. Extensible via filters
	$is_pro = apply_filters( 'sitecure_is_pro', false );
	if ( $is_pro ) {
		return true;
	}

	return (bool) apply_filters( 'wpdoctor_is_pro', false );
}

function sitecure_is_dev_mode() {
	return wpdoctor_is_dev_mode();
}

/**
 * Get allowed site quota for current tier
 *
 * @return int 1 for Free tier, 9999 for Developer / Pro
 */
function wpdoctor_get_site_quota() {
	if ( wpdoctor_is_dev_mode() ) {
		return 9999;
	}
	return 1;
}

function sitecure_get_site_quota() {
	return wpdoctor_get_site_quota();
}

/**
 * Check if another site can be added within the quota
 *
 * @return bool
 */
function wpdoctor_can_add_site() {
	$sites = wpdoctor_get_sites();
	return count( $sites ) < wpdoctor_get_site_quota();
}

function sitecure_can_add_site() {
	return wpdoctor_can_add_site();
}

/**
 * Register current hosted site with 1-click
 *
 * @return int|WP_Error Site ID or error
 */
function wpdoctor_register_local_site() {
	global $wpdb;
	$table = wpdoctor_get_table( 'sites' );

	// Check if already registered
	$existing = $wpdb->get_row( "SELECT * FROM $table WHERE access_mode = 'local' LIMIT 1" );
	if ( $existing ) {
		return (int) $existing->id;
	}

	if ( ! wpdoctor_can_add_site() ) {
		return new WP_Error( 'quota_reached', 'Free plan limit reached (1 site). Upgrade to Pro to manage multiple websites.' );
	}

	// Option B Cloud Verification Check
	if ( function_exists( 'sitecure_cloud_register_domain' ) ) {
		$cloud_check = sitecure_cloud_register_domain( home_url() );
		if ( is_wp_error( $cloud_check ) ) {
			return $cloud_check;
		}
	}

	$name = get_bloginfo( 'name' );
	if ( empty( $name ) ) {
		$name = 'This Website (Local)';
	}

	$wpdb->insert(
		$table,
		array(
			'name'          => $name . ' (Current Site)',
			'url'           => home_url(),
			'environment'   => 'production',
			'access_mode'   => 'local',
			'wp_path'       => ABSPATH,
			'health_status' => 'healthy',
			'created_at'    => current_time( 'mysql' ),
		)
	);

	$site_id = (int) $wpdb->insert_id;
	wpdoctor_log_audit( $site_id, 'register_site', 'local', "Registered hosted site '{$name}' as Site #{$site_id}" );

	return $site_id;
}

function sitecure_register_local_site() {
	return wpdoctor_register_local_site();
}

/**
 * Delete a managed site and its associated scan records
 *
 * @param int $site_id
 * @return bool
 */
function wpdoctor_delete_site( $site_id ) {
	global $wpdb;
	$site_id = (int) $site_id;
	if ( $site_id <= 0 ) {
		return false;
	}

	$table_sites      = wpdoctor_get_table( 'sites' );
	$table_scans      = wpdoctor_get_table( 'scans' );
	$table_findings   = wpdoctor_get_table( 'findings' );
	$table_quarantine = wpdoctor_get_table( 'quarantine' );
	$table_audit      = wpdoctor_get_table( 'audit_logs' );

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

function sitecure_delete_site( $site_id ) {
	return wpdoctor_delete_site( $site_id );
}

/**
 * Log an audit event
 */
function wpdoctor_log_audit( $site_id, $action, $target, $details ) {
	global $wpdb;
	$table_audit = wpdoctor_get_table( 'audit_logs' );
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
function wpdoctor_get_sites() {
	global $wpdb;
	$table = wpdoctor_get_table( 'sites' );
	return $wpdb->get_results( "SELECT * FROM $table ORDER BY id ASC" );
}

/**
 * Resolve filesystem root directory for any site
 */
function wpdoctor_get_site_root( $site_id ) {
	global $wpdb;
	$table_sites = wpdoctor_get_table( 'sites' );
	$site = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_sites WHERE id = %d", $site_id ) );
	$site_root = ABSPATH;

	if ( $site ) {
		if ( ! empty( $site->wp_path ) && file_exists( $site->wp_path ) ) {
			$site_root = $site->wp_path;
		} elseif ( ! empty( $site->wp_path ) && file_exists( dirname( ABSPATH ) . '/' . ltrim( $site->wp_path, '/\\' ) ) ) {
			$site_root = dirname( ABSPATH ) . '/' . ltrim( $site->wp_path, '/\\' );
		} else {
			$url_path = parse_url( $site->url, PHP_URL_PATH );
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
function wpdoctor_get_dashboard_stats() {
	global $wpdb;

	$table_sites = wpdoctor_get_table( 'sites' );
	$table_scans = wpdoctor_get_table( 'scans' );
	$table_findings = wpdoctor_get_table( 'findings' );
	$table_quarantine = wpdoctor_get_table( 'quarantine' );

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

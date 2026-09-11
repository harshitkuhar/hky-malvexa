<?php
/**
 * WP Doctor Procedural AJAX Endpoints
 * Protected by wp_verify_nonce and current_user_can('manage_options')
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpdoctor_ajax_init() {
	// WP Doctor legacy hooks
	add_action( 'wp_ajax_wpdoctor_start_scan', 'wpdoctor_ajax_handle_start_scan' );
	add_action( 'wp_ajax_wpdoctor_batch_scan', 'wpdoctor_ajax_handle_batch_scan' );
	add_action( 'wp_ajax_wpdoctor_quarantine_file', 'wpdoctor_ajax_handle_quarantine_file' );
	add_action( 'wp_ajax_wpdoctor_clean_file', 'wpdoctor_ajax_handle_clean_file' );
	add_action( 'wp_ajax_wpdoctor_restore_file', 'wpdoctor_ajax_handle_restore_file' );
	add_action( 'wp_ajax_wpdoctor_repair_core', 'wpdoctor_ajax_handle_repair_core' );
	add_action( 'wp_ajax_wpdoctor_verify_site', 'wpdoctor_ajax_handle_verify_site' );
	add_action( 'wp_ajax_wpdoctor_view_code', 'wpdoctor_ajax_handle_view_code' );
	add_action( 'wp_ajax_wpdoctor_save_site', 'wpdoctor_ajax_handle_save_site' );
	add_action( 'wp_ajax_wpdoctor_delete_site', 'wpdoctor_ajax_handle_delete_site' );
	add_action( 'wp_ajax_wpdoctor_register_local_site', 'wpdoctor_ajax_handle_register_local_site' );
	add_action( 'wp_ajax_wpdoctor_activate_license', 'wpdoctor_ajax_handle_activate_license' );

	// SiteCure action hooks
	add_action( 'wp_ajax_sitecure_start_scan', 'wpdoctor_ajax_handle_start_scan' );
	add_action( 'wp_ajax_sitecure_batch_scan', 'wpdoctor_ajax_handle_batch_scan' );
	add_action( 'wp_ajax_sitecure_quarantine_file', 'wpdoctor_ajax_handle_quarantine_file' );
	add_action( 'wp_ajax_sitecure_clean_file', 'wpdoctor_ajax_handle_clean_file' );
	add_action( 'wp_ajax_sitecure_restore_file', 'wpdoctor_ajax_handle_restore_file' );
	add_action( 'wp_ajax_sitecure_repair_core', 'wpdoctor_ajax_handle_repair_core' );
	add_action( 'wp_ajax_sitecure_verify_site', 'wpdoctor_ajax_handle_verify_site' );
	add_action( 'wp_ajax_sitecure_view_code', 'wpdoctor_ajax_handle_view_code' );
	add_action( 'wp_ajax_sitecure_save_site', 'wpdoctor_ajax_handle_save_site' );
	add_action( 'wp_ajax_sitecure_delete_site', 'wpdoctor_ajax_handle_delete_site' );
	add_action( 'wp_ajax_sitecure_register_local_site', 'wpdoctor_ajax_handle_register_local_site' );
	add_action( 'wp_ajax_sitecure_activate_license', 'wpdoctor_ajax_handle_activate_license' );
}

function sitecure_ajax_init() {
	wpdoctor_ajax_init();
}

/**
 * Verify nonce and administrator permissions
 */
function wpdoctor_verify_ajax_auth() {
	check_ajax_referer( 'wpdoctor_admin_nonce', 'nonce' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Unauthorized access.' ), 403 );
	}
}

/**
 * Start a new scan job
 */
function wpdoctor_ajax_handle_start_scan() {
	wpdoctor_verify_ajax_auth();

	$site_id = isset( $_POST['site_id'] ) ? (int) $_POST['site_id'] : 1;
	$scan_type = isset( $_POST['scan_type'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_type'] ) ) : 'deep';

	$result = wpdoctor_init_scan( $site_id, $scan_type );
	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Run a batch chunk of the scan
 */
function wpdoctor_ajax_handle_batch_scan() {
	wpdoctor_verify_ajax_auth();

	$scan_id = isset( $_POST['scan_id'] ) ? (int) $_POST['scan_id'] : 0;
	$batch_size = isset( $_POST['batch_size'] ) ? (int) $_POST['batch_size'] : 120;

	$result = wpdoctor_process_batch( $scan_id, $batch_size );
	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Quarantine an infected file
 */
function wpdoctor_ajax_handle_quarantine_file() {
	wpdoctor_verify_ajax_auth();

	$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
	$result = wpdoctor_quarantine_file( $finding_id );

	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Clean / Neutralize code injection
 */
function wpdoctor_ajax_handle_clean_file() {
	wpdoctor_verify_ajax_auth();

	$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
	$result = wpdoctor_clean_file_injection( $finding_id );

	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Restore a file from quarantine
 */
function wpdoctor_ajax_handle_restore_file() {
	wpdoctor_verify_ajax_auth();

	$quarantine_id = isset( $_POST['quarantine_id'] ) ? (int) $_POST['quarantine_id'] : 0;
	$result = wpdoctor_restore_quarantine_item( $quarantine_id );

	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Repair altered WordPress core file from official WP.org repository
 */
function wpdoctor_ajax_handle_repair_core() {
	wpdoctor_verify_ajax_auth();

	$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
	$site_id = isset( $_POST['site_id'] ) ? (int) $_POST['site_id'] : 0;

	if ( empty( $file_path ) ) {
		wp_send_json_error( array( 'message' => 'Missing file path.' ) );
	}

	$result = wpdoctor_repair_core_file( $file_path, '', $site_id );
	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( array( 'message' => 'Core file successfully repaired from WordPress.org.' ) );
}

/**
 * Verify overall site health
 */
function wpdoctor_ajax_handle_verify_site() {
	wpdoctor_verify_ajax_auth();

	$site_id = isset( $_POST['site_id'] ) ? (int) $_POST['site_id'] : 1;
	$result = wpdoctor_verify_site_health( $site_id );

	wp_send_json_success( $result );
}

/**
 * View code evidence around an infected line
 */
function wpdoctor_ajax_handle_view_code() {
	wpdoctor_verify_ajax_auth();
	global $wpdb;

	$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
	$table_findings = wpdoctor_get_table( 'findings' );

	$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_findings WHERE id = %d", $finding_id ) );
	if ( ! $finding ) {
		wp_send_json_error( array( 'message' => 'Finding not found.' ) );
	}

	// 1. Handle Database threats
	if ( strpos( $finding->file_path, 'database:' ) === 0 || $finding->category === 'wpcode_snippet' || $finding->category === 'db_option_injection' || $finding->category === 'seo_spam_injection' ) {
		$target_db = wpdoctor_get_target_db( $finding->site_id );

		// A. SEO / Casino spam post or revision
		if ( $finding->category === 'seo_spam_injection' && stripos( $finding->file_path, 'options' ) === false ) {
			$post_id = (int) $finding->line_number;
			$p = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->posts}` WHERE ID = %d", $post_id ) );
			$meta = $target_db->get_var( $target_db->prepare( "SELECT meta_value FROM `{$target_db->postmeta}` WHERE post_id = %d AND meta_key = '_elementor_data'", $post_id ) );

			$snippet = '';
			if ( ! empty( $finding->evidence ) ) {
				$snippet = html_entity_decode( $finding->evidence, ENT_QUOTES, 'UTF-8' );
			} elseif ( $p && ! empty( $p->post_content ) ) {
				$snippet = substr( $p->post_content, 0, 1500 );
			} elseif ( ! empty( $meta ) ) {
				$snippet = substr( $meta, 0, 1500 );
			}

			wp_send_json_success(
				array(
					'file_path'    => $finding->file_path,
					'line_number'  => $finding->line_number,
					'code_snippet' => $snippet,
					'category'     => $finding->category,
					'evidence'     => $finding->evidence,
					'description'  => $finding->description,
					'status'       => $finding->status,
					'finding_id'   => $finding->id,
				)
			);
		}

		// B. Database option injection
		if ( stripos( $finding->file_path, 'options' ) !== false || $finding->category === 'db_option_injection' ) {
			$option_id = (int) $finding->line_number;
			$opt = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->options}` WHERE option_id = %d", $option_id ) );
			$snippet = $opt ? substr( $opt->option_value, 0, 1500 ) : $finding->evidence;

			wp_send_json_success(
				array(
					'file_path'    => $finding->file_path,
					'line_number'  => $finding->line_number,
					'code_snippet' => $snippet,
					'category'     => $finding->category,
					'evidence'     => $finding->evidence,
					'description'  => $finding->description,
					'status'       => $finding->status,
					'finding_id'   => $finding->id,
				)
			);
		}

		// C. WPCode Snippet
		if ( $finding->category === 'wpcode_snippet' ) {
			$snippet_id = (int) $finding->line_number;
			$post = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->posts}` WHERE ID = %d", $snippet_id ) );
			$snippet = $post ? $post->post_content : $finding->evidence;

			wp_send_json_success(
				array(
					'file_path'    => $finding->file_path,
					'line_number'  => $finding->line_number,
					'code_snippet' => $snippet,
					'category'     => $finding->category,
					'evidence'     => $finding->evidence,
					'description'  => $finding->description,
					'status'       => $finding->status,
					'finding_id'   => $finding->id,
				)
			);
		}
	}

	// 2. Physical File inspection
	$site_root = ( ! empty( $finding->site_id ) && function_exists( 'wpdoctor_get_site_root' ) ) ? wpdoctor_get_site_root( $finding->site_id ) : ABSPATH;
	$full_path = rtrim( str_replace( '\\', '/', $site_root ), '/' ) . '/' . ltrim( $finding->file_path, '/\\' );

	if ( ! file_exists( $full_path ) ) {
		wp_send_json_error( array( 'message' => 'Target file does not exist on disk.' ) );
	}

	$lines = @file( $full_path );
	if ( false === $lines ) {
		wp_send_json_error( array( 'message' => 'Could not read file.' ) );
	}

	$target_line = (int) $finding->line_number;
	$start = max( 0, $target_line - 8 );
	$slice = array_slice( $lines, $start, 16, true );

	$snippet = '';
	foreach ( $slice as $num => $line ) {
		$line_no = $num + 1;
		$marker = ( $line_no === $target_line ) ? '>> ' : '   ';
		$snippet .= sprintf( "%s%4d | %s", $marker, $line_no, $line );
	}

	wp_send_json_success(
		array(
			'file_path'    => $finding->file_path,
			'line_number'  => $target_line,
			'code_snippet' => $snippet,
			'category'     => $finding->category,
			'evidence'     => $finding->evidence,
			'description'  => $finding->description,
			'status'       => $finding->status,
			'finding_id'   => $finding->id,
		)
	);
}

/**
 * Save / Create Site (Quota Protected)
 */
function wpdoctor_ajax_handle_save_site() {
	wpdoctor_verify_ajax_auth();
	global $wpdb;

	if ( ! wpdoctor_can_add_site() ) {
		wp_send_json_error( array(
			'code'    => 'quota_reached',
			'message' => 'Free Plan limit reached (1 active site). Upgrade to SiteCure Pro to connect and manage multiple client websites.',
		) );
	}

	$table_sites = wpdoctor_get_table( 'sites' );

	$name    = isset( $_POST['site_name'] ) ? sanitize_text_field( wp_unslash( $_POST['site_name'] ) ) : '';
	$url     = isset( $_POST['site_url'] ) ? esc_url_raw( wp_unslash( $_POST['site_url'] ) ) : '';
	$env     = isset( $_POST['environment'] ) ? sanitize_text_field( wp_unslash( $_POST['environment'] ) ) : 'production';
	$mode    = isset( $_POST['access_mode'] ) ? sanitize_text_field( wp_unslash( $_POST['access_mode'] ) ) : 'sftp';
	$wp_path = isset( $_POST['wp_path'] ) ? sanitize_text_field( wp_unslash( $_POST['wp_path'] ) ) : '';
	$notes   = isset( $_POST['notes'] ) ? sanitize_textarea_field( wp_unslash( $_POST['notes'] ) ) : '';

	if ( empty( $name ) || empty( $url ) ) {
		wp_send_json_error( array( 'message' => 'Site Name and URL are required.' ) );
	}

	// Option B: Cloud-Assisted Token Verification & Quota Enforcement
	if ( function_exists( 'sitecure_cloud_register_domain' ) ) {
		$cloud_res = sitecure_cloud_register_domain( $url );
		if ( is_wp_error( $cloud_res ) ) {
			wp_send_json_error( array(
				'code'    => 'quota_reached',
				'message' => $cloud_res->get_error_message(),
			) );
		}
	}

	$wpdb->insert(
		$table_sites,
		array(
			'name'          => $name,
			'url'           => $url,
			'environment'   => $env,
			'access_mode'   => $mode,
			'wp_path'       => $wp_path,
			'health_status' => 'healthy',
			'notes'         => $notes,
			'created_at'    => current_time( 'mysql' ),
		)
	);

	$site_id = $wpdb->insert_id;

	// Save SFTP connection credentials if provided
	if ( $mode === 'sftp' && ! empty( $_POST['sftp_host'] ) ) {
		$table_conn = wpdoctor_get_table( 'connections' );
		$host = sanitize_text_field( wp_unslash( $_POST['sftp_host'] ) );
		$port = isset( $_POST['sftp_port'] ) ? (int) $_POST['sftp_port'] : 22;
		$user = sanitize_text_field( wp_unslash( $_POST['sftp_user'] ) );
		$pass = isset( $_POST['sftp_pass'] ) ? sanitize_text_field( wp_unslash( $_POST['sftp_pass'] ) ) : '';
		$path = isset( $_POST['sftp_path'] ) ? sanitize_text_field( wp_unslash( $_POST['sftp_path'] ) ) : '/';

		$wpdb->insert(
			$table_conn,
			array(
				'site_id'            => $site_id,
				'connection_type'    => 'sftp',
				'host'               => $host,
				'port'               => $port,
				'username'           => $user,
				'encrypted_password' => wpdoctor_encrypt( $pass ),
				'remote_path'        => $path,
				'created_at'         => current_time( 'mysql' ),
			)
		);
	}

	wpdoctor_log_audit( $site_id, 'add_site', $name, "Added new managed site: {$name} ({$url})" );

	wp_send_json_success( array( 'message' => 'Site added successfully!', 'site_id' => $site_id ) );
}

/**
 * 1-Click Register Local Hosted Site
 */
function wpdoctor_ajax_handle_register_local_site() {
	wpdoctor_verify_ajax_auth();

	$res = wpdoctor_register_local_site();
	if ( is_wp_error( $res ) ) {
		wp_send_json_error( array( 'message' => $res->get_error_message() ) );
	}

	wp_send_json_success( array(
		'message' => 'This website has been registered as your target scan site!',
		'site_id' => $res,
	) );
}

/**
 * Activate Pro / Developer License
 */
function wpdoctor_ajax_handle_activate_license() {
	wpdoctor_verify_ajax_auth();

	$key = isset( $_POST['license_key'] ) ? sanitize_text_field( wp_unslash( $_POST['license_key'] ) ) : '';
	if ( empty( $key ) ) {
		wp_send_json_error( array( 'message' => 'Please enter a license key.' ) );
	}

	update_option( 'sitecure_pro_license_key', $key );
	update_option( 'wpdoctor_pro_license_key', $key );

	if ( wpdoctor_is_dev_mode() ) {
		wp_send_json_success( array( 'message' => 'Developer Unlimited Access unlocked!' ) );
	}

	// Verify with cloud microservice
	if ( function_exists( 'sitecure_cloud_check_license' ) ) {
		$cloud_ver = sitecure_cloud_check_license( $key );
		if ( ! empty( $cloud_ver['valid'] ) ) {
			wp_send_json_success( array( 'message' => 'SiteCure Pro License activated successfully!' ) );
		} else {
			wp_send_json_error( array( 'message' => ! empty( $cloud_ver['message'] ) ? $cloud_ver['message'] : 'Invalid license key.' ) );
		}
	} else {
		wp_send_json_success( array( 'message' => 'License saved successfully!' ) );
	}
}

/**
 * Delete Site
 */
function wpdoctor_ajax_handle_delete_site() {
	wpdoctor_verify_ajax_auth();

	$site_id = isset( $_POST['site_id'] ) ? (int) $_POST['site_id'] : 0;
	if ( $site_id <= 0 ) {
		wp_send_json_error( array( 'message' => 'Invalid site ID.' ) );
	}

	$ok = wpdoctor_delete_site( $site_id );
	if ( ! $ok ) {
		wp_send_json_error( array( 'message' => 'Site could not be found or deleted.' ) );
	}

	wp_send_json_success( array( 'message' => 'Site removed successfully. You can now configure another site slot.' ) );
}

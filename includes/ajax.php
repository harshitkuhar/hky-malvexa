<?php
/**
 * HKY MalVexa Procedural AJAX Endpoints
 * Protected by wp_verify_nonce and current_user_can('manage_options')
 */
// phpcs:disable WordPress.Security.NonceVerification.Missing -- All AJAX endpoints strictly authenticated via check_ajax_referer and manage_options capability in hkymalvexa_verify_ajax_auth().
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom database tables used for hkymalvexa sites and connections.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function hkymalvexa_ajax_init() {
	// HKY MalVexa action hooks
	add_action( 'wp_ajax_hkymalvexa_start_scan', 'hkymalvexa_ajax_handle_start_scan' );
	add_action( 'wp_ajax_hkymalvexa_batch_scan', 'hkymalvexa_ajax_handle_batch_scan' );
	add_action( 'wp_ajax_hkymalvexa_quarantine_file', 'hkymalvexa_ajax_handle_quarantine_file' );
	add_action( 'wp_ajax_hkymalvexa_clean_file', 'hkymalvexa_ajax_handle_clean_file' );
	add_action( 'wp_ajax_hkymalvexa_restore_file', 'hkymalvexa_ajax_handle_restore_file' );
	add_action( 'wp_ajax_hkymalvexa_repair_core', 'hkymalvexa_ajax_handle_repair_core' );
	add_action( 'wp_ajax_hkymalvexa_verify_site', 'hkymalvexa_ajax_handle_verify_site' );
	add_action( 'wp_ajax_hkymalvexa_view_code', 'hkymalvexa_ajax_handle_view_code' );
	add_action( 'wp_ajax_hkymalvexa_save_site', 'hkymalvexa_ajax_handle_save_site' );
	add_action( 'wp_ajax_hkymalvexa_delete_site', 'hkymalvexa_ajax_handle_delete_site' );
	add_action( 'wp_ajax_hkymalvexa_register_local_site', 'hkymalvexa_ajax_handle_register_local_site' );
}

/**
 * Verify nonce and administrator permissions
 */
function hkymalvexa_verify_ajax_auth() {
	check_ajax_referer( 'hkymalvexa_admin_nonce', 'nonce' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Unauthorized access.' ), 403 );
	}
}

/**
 * Start a new scan job
 */
function hkymalvexa_ajax_handle_start_scan() {
	hkymalvexa_verify_ajax_auth();

	$site_id = ( isset( $_POST['site_id'] ) && (int) $_POST['site_id'] > 0 ) ? (int) $_POST['site_id'] : hkymalvexa_get_current_site_id();
	$scan_type = isset( $_POST['scan_type'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_type'] ) ) : 'deep';

	$result = hkymalvexa_init_scan( $site_id, $scan_type );
	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Run a batch chunk of the scan
 */
function hkymalvexa_ajax_handle_batch_scan() {
	hkymalvexa_verify_ajax_auth();

	$scan_id = isset( $_POST['scan_id'] ) ? (int) $_POST['scan_id'] : 0;
	$batch_size = isset( $_POST['batch_size'] ) ? (int) $_POST['batch_size'] : 120;

	$result = hkymalvexa_process_batch( $scan_id, $batch_size );
	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Quarantine an infected file
 */
function hkymalvexa_ajax_handle_quarantine_file() {
	hkymalvexa_verify_ajax_auth();

	$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
	$result = hkymalvexa_quarantine_file( $finding_id );

	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Clean / Neutralize code injection
 */
function hkymalvexa_ajax_handle_clean_file() {
	hkymalvexa_verify_ajax_auth();

	$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
	$result = hkymalvexa_clean_file_injection( $finding_id );

	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Restore a file or database record from quarantine
 */
function hkymalvexa_ajax_handle_restore_file() {
	hkymalvexa_verify_ajax_auth();

	$quarantine_id = isset( $_POST['quarantine_id'] ) ? (int) $_POST['quarantine_id'] : 0;
	$result = function_exists( 'hkymalvexa_restore_file' ) 
		? hkymalvexa_restore_file( $quarantine_id ) 
		: new WP_Error( 'missing_handler', 'Restore function not available.' );

	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( $result );
}

/**
 * Repair altered WordPress core file from official WP.org repository
 */
function hkymalvexa_ajax_handle_repair_core() {
	hkymalvexa_verify_ajax_auth();

	$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
	$site_id = isset( $_POST['site_id'] ) ? (int) $_POST['site_id'] : 0;

	if ( empty( $file_path ) ) {
		wp_send_json_error( array( 'message' => 'Missing file path.' ) );
	}

	$result = hkymalvexa_repair_core_file( $file_path, '', $site_id );
	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}

	wp_send_json_success( array( 'message' => 'Core file successfully repaired from WordPress.org.' ) );
}

/**
 * Verify overall site health
 */
function hkymalvexa_ajax_handle_verify_site() {
	hkymalvexa_verify_ajax_auth();

	$site_id = isset( $_POST['site_id'] ) ? (int) $_POST['site_id'] : 1;
	$result = hkymalvexa_verify_site_health( $site_id );

	wp_send_json_success( $result );
}

/**
 * View code evidence around an infected line
 */
function hkymalvexa_ajax_handle_view_code() {
	hkymalvexa_verify_ajax_auth();
	global $wpdb;

	$finding_id = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
	$table_findings = hkymalvexa_get_table( 'findings' );

	$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_findings WHERE id = %d", $finding_id ) );
	if ( ! $finding ) {
		wp_send_json_error( array( 'message' => 'Finding not found.' ) );
	}

	// 1. Handle Database threats
	if ( strpos( $finding->file_path, 'database:' ) === 0 || $finding->category === 'wpcode_snippet' || $finding->category === 'db_option_injection' || $finding->category === 'seo_spam_injection' ) {
		$target_db = hkymalvexa_get_target_db( $finding->site_id );

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

			$code_html = '<pre style="margin:0;padding:12px;font-family:monospace;white-space:pre-wrap;word-break:break-all;color:#e2e8f0;font-size:12px;line-height:1.5;">' . esc_html( $snippet ) . '</pre>';
			wp_send_json_success(
				array(
					'file_path'    => $finding->file_path,
					'line_number'  => $finding->line_number,
					'code_snippet' => $snippet,
					'code_html'    => $code_html,
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

			$code_html = '<pre style="margin:0;padding:12px;font-family:monospace;white-space:pre-wrap;word-break:break-all;color:#e2e8f0;font-size:12px;line-height:1.5;">' . esc_html( $snippet ) . '</pre>';
			wp_send_json_success(
				array(
					'file_path'    => $finding->file_path,
					'line_number'  => $finding->line_number,
					'code_snippet' => $snippet,
					'code_html'    => $code_html,
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

			$code_html = '<pre style="margin:0;padding:12px;font-family:monospace;white-space:pre-wrap;word-break:break-all;color:#e2e8f0;font-size:12px;line-height:1.5;">' . esc_html( $snippet ) . '</pre>';
			wp_send_json_success(
				array(
					'file_path'    => $finding->file_path,
					'line_number'  => $finding->line_number,
					'code_snippet' => $snippet,
					'code_html'    => $code_html,
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
	$site_root = ( ! empty( $finding->site_id ) && function_exists( 'hkymalvexa_get_site_root' ) ) ? hkymalvexa_get_site_root( $finding->site_id ) : ABSPATH;
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

	$code_html = '<pre style="margin:0;padding:12px;font-family:monospace;white-space:pre-wrap;word-break:break-all;color:#e2e8f0;font-size:12px;line-height:1.5;">' . esc_html( $snippet ) . '</pre>';
	wp_send_json_success(
		array(
			'file_path'    => $finding->file_path,
			'line_number'  => $target_line,
			'code_snippet' => $snippet,
			'code_html'    => $code_html,
			'category'     => $finding->category,
			'evidence'     => $finding->evidence,
			'description'  => $finding->description,
			'status'       => $finding->status,
			'finding_id'   => $finding->id,
		)
	);
}

/**
 * Save / Create Site
 */
function hkymalvexa_ajax_handle_save_site() {
	hkymalvexa_verify_ajax_auth();
	global $wpdb;

	$table_sites = hkymalvexa_get_table( 'sites' );

	$name    = isset( $_POST['site_name'] ) ? sanitize_text_field( wp_unslash( $_POST['site_name'] ) ) : '';
	$url     = isset( $_POST['site_url'] ) ? esc_url_raw( wp_unslash( $_POST['site_url'] ) ) : '';
	$env     = isset( $_POST['environment'] ) ? sanitize_text_field( wp_unslash( $_POST['environment'] ) ) : 'production';
	$mode    = isset( $_POST['access_mode'] ) ? sanitize_text_field( wp_unslash( $_POST['access_mode'] ) ) : 'sftp';
	$wp_path = isset( $_POST['wp_path'] ) ? sanitize_text_field( wp_unslash( $_POST['wp_path'] ) ) : '';
	$notes   = isset( $_POST['notes'] ) ? sanitize_textarea_field( wp_unslash( $_POST['notes'] ) ) : '';

	if ( empty( $name ) || empty( $url ) ) {
		wp_send_json_error( array( 'message' => 'Site Name and URL are required.' ) );
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
		$table_conn = hkymalvexa_get_table( 'connections' );
		$host = isset( $_POST['sftp_host'] ) ? sanitize_text_field( wp_unslash( $_POST['sftp_host'] ) ) : '';
		$port = isset( $_POST['sftp_port'] ) ? (int) $_POST['sftp_port'] : 22;
		$user = isset( $_POST['sftp_user'] ) ? sanitize_text_field( wp_unslash( $_POST['sftp_user'] ) ) : '';
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
				'encrypted_password' => hkymalvexa_encrypt( $pass ),
				'remote_path'        => $path,
				'created_at'         => current_time( 'mysql' ),
			)
		);
	}

	hkymalvexa_log_audit( $site_id, 'add_site', $name, "Added new managed site: {$name} ({$url})" );

	wp_send_json_success( array( 'message' => 'Site added successfully!', 'site_id' => $site_id ) );
}

/**
 * 1-Click Register Local Hosted Site
 */
function hkymalvexa_ajax_handle_register_local_site() {
	hkymalvexa_verify_ajax_auth();

	$res = hkymalvexa_register_local_site();
	if ( is_wp_error( $res ) ) {
		wp_send_json_error( array( 'message' => $res->get_error_message() ) );
	}

	wp_send_json_success( array(
		'message' => 'This website has been registered as your target scan site!',
		'site_id' => $res,
	) );
}

/**
 * Delete Site
 */
function hkymalvexa_ajax_handle_delete_site() {
	hkymalvexa_verify_ajax_auth();

	$site_id = isset( $_POST['site_id'] ) ? (int) $_POST['site_id'] : 0;
	if ( $site_id <= 0 ) {
		wp_send_json_error( array( 'message' => 'Invalid site ID.' ) );
	}

	$ok = hkymalvexa_delete_site( $site_id );
	if ( ! $ok ) {
		wp_send_json_error( array( 'message' => 'Site could not be found or deleted.' ) );
	}

	wp_send_json_success( array( 'message' => 'Site removed successfully.' ) );
}

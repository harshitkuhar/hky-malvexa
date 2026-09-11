<?php
/**
 * SiteCure Procedural Admin Management & Views Controller
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function sitecure_admin_init() {
	add_action( 'admin_menu', 'sitecure_register_admin_menus' );
	add_action( 'admin_enqueue_scripts', 'sitecure_admin_enqueue_assets' );
}

/**
 * Register Admin Menu and Submenus
 */
function sitecure_register_admin_menus() {
	$capability = 'manage_options';

	// Top level menu
	add_menu_page(
		__( 'SiteCure', 'sitecure' ),
		__( 'SiteCure', 'sitecure' ),
		$capability,
		'sitecure',
		'sitecure_render_dashboard',
		'dashicons-shield-alt',
		3
	);

	// Primary Submenus
	add_submenu_page(
		'sitecure',
		__( 'Dashboard — SiteCure', 'sitecure' ),
		__( 'Dashboard', 'sitecure' ),
		$capability,
		'sitecure',
		'sitecure_render_dashboard'
	);

	add_submenu_page(
		'sitecure',
		__( 'Managed Sites — SiteCure', 'sitecure' ),
		__( 'Managed Sites', 'sitecure' ),
		$capability,
		'sitecure-sites',
		'sitecure_render_sites'
	);

	add_submenu_page(
		'sitecure',
		__( 'Scan & Findings — SiteCure', 'sitecure' ),
		__( 'Scan & Findings', 'sitecure' ),
		$capability,
		'sitecure-findings',
		'sitecure_render_findings'
	);

	add_submenu_page(
		'sitecure',
		__( 'Quarantine Vault — SiteCure', 'sitecure' ),
		__( 'Quarantine Vault', 'sitecure' ),
		$capability,
		'sitecure-quarantine',
		'sitecure_render_quarantine'
	);

	add_submenu_page(
		'sitecure',
		__( 'Audit Logs — SiteCure', 'sitecure' ),
		__( 'Audit Logs', 'sitecure' ),
		$capability,
		'sitecure-audit-logs',
		'sitecure_render_audit_logs'
	);
}

/**
 * Enqueue CSS and JS assets on SiteCure admin pages
 */
function sitecure_admin_enqueue_assets( $hook ) {
	if ( strpos( $hook, 'sitecure' ) === false ) {
		return;
	}

	$css_file = SITECURE_PLUGIN_DIR . 'admin/css/sitecure-admin.css';
	$js_file  = SITECURE_PLUGIN_DIR . 'admin/js/sitecure-admin.js';

	$css_url = SITECURE_PLUGIN_URL . 'admin/css/' . basename( $css_file );
	$js_url  = SITECURE_PLUGIN_URL . 'admin/js/' . basename( $js_file );
	$css_ver = file_exists( $css_file ) ? (string) filemtime( $css_file ) : SITECURE_VERSION;
	$js_ver  = file_exists( $js_file ) ? (string) filemtime( $js_file ) : SITECURE_VERSION;

	// Admin stylesheet
	wp_enqueue_style(
		'sitecure-admin-css',
		$css_url,
		array(),
		$css_ver
	);

	// Admin JavaScript
	wp_enqueue_script(
		'sitecure-admin-js',
		$js_url,
		array( 'jquery' ),
		$js_ver,
		true
	);

	$client_data = array(
		'ajax_url' => admin_url( 'admin-ajax.php' ),
		'nonce'    => wp_create_nonce( 'sitecure_admin_nonce' ),
		'strings'  => array(
			'scanning'    => __( 'Scanning in progress...', 'sitecure' ),
			'completed'   => __( 'Scan completed successfully!', 'sitecure' ),
			'confirm_q'   => __( 'Are you sure you want to quarantine this file? A safety backup will be created.', 'sitecure' ),
			'confirm_r'   => __( 'Restore this file from quarantine back to its original location?', 'sitecure' ),
			'confirm_c'   => __( 'Download pristine official core file from WordPress.org and overwrite?', 'sitecure' ),
		),
	);

	wp_localize_script( 'sitecure-admin-js', 'sitecure_data', $client_data );
}

/**
 * View Renderers
 */
function sitecure_render_dashboard() {
	require_once SITECURE_PLUGIN_DIR . 'admin/views/dashboard.php';
}

function sitecure_render_sites() {
	require_once SITECURE_PLUGIN_DIR . 'admin/views/sites.php';
}

function sitecure_render_scan_center() {
	require_once SITECURE_PLUGIN_DIR . 'admin/views/scan-center.php';
}

function sitecure_render_findings() {
	require_once SITECURE_PLUGIN_DIR . 'admin/views/findings.php';
}

function sitecure_render_quarantine() {
	require_once SITECURE_PLUGIN_DIR . 'admin/views/quarantine.php';
}

function sitecure_render_audit_logs() {
	require_once SITECURE_PLUGIN_DIR . 'admin/views/audit-logs.php';
}

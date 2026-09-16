<?php
/**
 * HKY MalVexa Procedural Admin Management & Views Controller
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function hkymalvexa_admin_init() {
	add_action( 'admin_menu', 'hkymalvexa_register_admin_menus' );
	add_action( 'admin_enqueue_scripts', 'hkymalvexa_admin_enqueue_assets' );
}

/**
 * Register Admin Menu and Submenus
 */
function hkymalvexa_register_admin_menus() {
	$capability = 'manage_options';

	// Top level menu
	add_menu_page(
		__( 'HKY MalVexa', 'hky-malvexa' ),
		__( 'HKY MalVexa', 'hky-malvexa' ),
		$capability,
		'hky-malvexa',
		'hkymalvexa_render_dashboard',
		'dashicons-shield-alt',
		80
	);

	// Primary Submenus
	add_submenu_page(
		'hky-malvexa',
		__( 'Dashboard — HKY MalVexa', 'hky-malvexa' ),
		__( 'Dashboard', 'hky-malvexa' ),
		$capability,
		'hky-malvexa',
		'hkymalvexa_render_dashboard'
	);

	add_submenu_page(
		'hky-malvexa',
		__( 'Scan & Findings — HKY MalVexa', 'hky-malvexa' ),
		__( 'Scan & Findings', 'hky-malvexa' ),
		$capability,
		'hkymalvexa-findings',
		'hkymalvexa_render_findings'
	);

	add_submenu_page(
		'hky-malvexa',
		__( 'Quarantine Vault — HKY MalVexa', 'hky-malvexa' ),
		__( 'Quarantine Vault', 'hky-malvexa' ),
		$capability,
		'hkymalvexa-quarantine',
		'hkymalvexa_render_quarantine'
	);

	add_submenu_page(
		'hky-malvexa',
		__( 'Audit Logs — HKY MalVexa', 'hky-malvexa' ),
		__( 'Audit Logs', 'hky-malvexa' ),
		$capability,
		'hkymalvexa-audit-logs',
		'hkymalvexa_render_audit_logs'
	);
}

/**
 * Enqueue CSS and JS assets on HKY MalVexa admin pages
 */
function hkymalvexa_admin_enqueue_assets( $hook ) {
	if ( strpos( $hook, 'hky-malvexa' ) === false && strpos( $hook, 'hkymalvexa' ) === false ) {
		return;
	}

	$css_file = HKYMALVEXA_PLUGIN_DIR . 'admin/css/hky-malvexa-admin.css';
	$js_file  = HKYMALVEXA_PLUGIN_DIR . 'admin/js/hky-malvexa-admin.js';

	$css_url = HKYMALVEXA_PLUGIN_URL . 'admin/css/' . basename( $css_file );
	$js_url  = HKYMALVEXA_PLUGIN_URL . 'admin/js/' . basename( $js_file );
	$css_ver = file_exists( $css_file ) ? (string) filemtime( $css_file ) : HKYMALVEXA_VERSION;
	$js_ver  = file_exists( $js_file ) ? (string) filemtime( $js_file ) : HKYMALVEXA_VERSION;

	// Core Dashicons
	wp_enqueue_style( 'dashicons' );

	// Admin stylesheet
	wp_enqueue_style(
		'hky-malvexa-admin-css',
		$css_url,
		array( 'dashicons' ),
		$css_ver
	);

	// Admin JavaScript
	wp_enqueue_script(
		'hky-malvexa-admin-js',
		$js_url,
		array( 'jquery' ),
		$js_ver,
		true
	);

	$client_data = array(
		'ajax_url' => admin_url( 'admin-ajax.php' ),
		'nonce'    => wp_create_nonce( 'hkymalvexa_admin_nonce' ),
		'strings'  => array(
			'scanning'    => __( 'Scanning in progress...', 'hky-malvexa' ),
			'completed'   => __( 'Scan completed successfully!', 'hky-malvexa' ),
			'confirm_q'   => __( 'Are you sure you want to quarantine this file? A safety backup will be created.', 'hky-malvexa' ),
			'confirm_r'   => __( 'Restore this file from quarantine back to its original location?', 'hky-malvexa' ),
			'confirm_c'   => __( 'Download pristine official core file from WordPress.org and overwrite?', 'hky-malvexa' ),
		),
	);

	wp_localize_script( 'hky-malvexa-admin-js', 'hkymalvexa_data', $client_data );
}

/**
 * View Renderers
 */
function hkymalvexa_render_dashboard() {
	require_once HKYMALVEXA_PLUGIN_DIR . 'admin/views/dashboard.php';
}

function hkymalvexa_render_sites() {
	wp_safe_redirect( admin_url( 'admin.php?page=hkymalvexa-findings' ) );
	exit;
}

function hkymalvexa_render_scan_center() {
	require_once HKYMALVEXA_PLUGIN_DIR . 'admin/views/scan-center.php';
}

function hkymalvexa_render_findings() {
	require_once HKYMALVEXA_PLUGIN_DIR . 'admin/views/findings.php';
}

function hkymalvexa_render_quarantine() {
	require_once HKYMALVEXA_PLUGIN_DIR . 'admin/views/quarantine.php';
}

function hkymalvexa_render_audit_logs() {
	require_once HKYMALVEXA_PLUGIN_DIR . 'admin/views/audit-logs.php';
}

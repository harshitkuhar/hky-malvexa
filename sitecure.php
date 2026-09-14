<?php
/**
 * Plugin Name:       SiteCure
 * Plugin URI:        https://github.com/harshitkuhar/sitecure
 * Description:       Surgical WordPress malware scanner, blackhat SEO & casino spam cleaner, core integrity repair, and isolated quarantine vault with 1-click rollback.
 * Version:           1.0.0
 * Author:            SiteCure Team - Harshit
 * Author URI:        https://github.com/harshitkuhar
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       sitecure
 * Requires at least: 6.0
 * Tested up to:      7.1
 * Requires PHP:      7.4
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

// SiteCure plugin constants
if ( ! defined( 'SITECURE_VERSION' ) ) {
	define( 'SITECURE_VERSION', '1.0.0' );
}
if ( ! defined( 'SITECURE_PLUGIN_DIR' ) ) {
	define( 'SITECURE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}
if ( ! defined( 'SITECURE_PLUGIN_URL' ) ) {
	define( 'SITECURE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}
if ( ! defined( 'SITECURE_BASENAME' ) ) {
	define( 'SITECURE_BASENAME', plugin_basename( __FILE__ ) );
}

/**
 * Self-healing safeguard:
 * If any core SiteCure plugin file was accidentally moved to quarantine, automatically restore it!
 */
function sitecure_self_heal_missing_files() {
	$sitecure_includes = array(
		'db.php', 'crypto.php', 'signatures.php', 'classifier.php', 'integrity.php',
		'malware-detector.php', 'uploads-analyzer.php', 'config-analyzer.php',
		'persistence.php', 'database-scanner.php', 'engine.php', 'quarantine.php',
		'restorer.php', 'verifier.php', 'cloud-verifier.php', 'admin.php', 'ajax.php',
	);

	$upload_dir = wp_upload_dir();
	$sitecure_quarantine_dirs = array(
		$upload_dir['basedir'] . '/sitecure-quarantine',
	);

	foreach ( $sitecure_includes as $file ) {
		$target = SITECURE_PLUGIN_DIR . 'includes/' . $file;
		if ( ! file_exists( $target ) ) {
			foreach ( $sitecure_quarantine_dirs as $qdir ) {
				if ( is_dir( $qdir ) ) {
					$matches = glob( $qdir . '/' . $file . '.*.quarantined' );
					if ( ! empty( $matches ) ) {
						$latest = end( $matches );
						@copy( $latest, $target );
						break;
					}
				}
			}
		}
	}
}
sitecure_self_heal_missing_files();

/**
 * Safe procedural core inclusions
 */
$sitecure_core_files = array(
	'db.php', 'crypto.php', 'signatures.php', 'classifier.php', 'integrity.php',
	'malware-detector.php', 'uploads-analyzer.php', 'config-analyzer.php',
	'persistence.php', 'database-scanner.php', 'engine.php', 'quarantine.php',
	'restorer.php', 'verifier.php', 'cloud-verifier.php', 'admin.php', 'ajax.php',
);

foreach ( $sitecure_core_files as $sitecure_core_file ) {
	$sitecure_core_path = SITECURE_PLUGIN_DIR . 'includes/' . $sitecure_core_file;
	if ( file_exists( $sitecure_core_path ) ) {
		require_once $sitecure_core_path;
	}
}

/**
 * Activation Hook
 */
function sitecure_on_activation() {
	if ( function_exists( 'sitecure_install_database_tables' ) ) {
		sitecure_install_database_tables();
	}
}
register_activation_hook( __FILE__, 'sitecure_on_activation' );

/**
 * Deactivation Hook
 */
function sitecure_on_deactivation() {
	wp_clear_scheduled_hook( 'sitecure_scheduled_scan' );
}
register_deactivation_hook( __FILE__, 'sitecure_on_deactivation' );

/**
 * Initialize SiteCure plugin
 */
function sitecure_bootstrap() {
	if ( function_exists( 'sitecure_admin_init' ) ) {
		sitecure_admin_init();
	}
	if ( function_exists( 'sitecure_ajax_init' ) ) {
		sitecure_ajax_init();
	}
}
add_action( 'plugins_loaded', 'sitecure_bootstrap' );

<?php
/**
 * Plugin Name:       HKY MalVexa
 * Plugin URI:        https://github.com/harshitkuhar/hky-malvexa
 * Description:       Surgical WordPress malware scanner, blackhat SEO & casino spam cleaner, core integrity repair, and isolated quarantine vault with 1-click rollback.
 * Version:           1.0.0
 * Author:            HKY MalVexa Team - Harshit
 * Author URI:        https://github.com/harshitkuhar
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       hky-malvexa
 * Requires at least: 6.0
 * Tested up to:      7.1
 * Requires PHP:      7.4
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

// HKY MalVexa plugin constants
if ( ! defined( 'HKYMALVEXA_VERSION' ) ) {
	define( 'HKYMALVEXA_VERSION', '1.0.0' );
}
if ( ! defined( 'HKYMALVEXA_PLUGIN_DIR' ) ) {
	define( 'HKYMALVEXA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}
if ( ! defined( 'HKYMALVEXA_PLUGIN_URL' ) ) {
	define( 'HKYMALVEXA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}
if ( ! defined( 'HKYMALVEXA_BASENAME' ) ) {
	define( 'HKYMALVEXA_BASENAME', plugin_basename( __FILE__ ) );
}

/**
 * Safe procedural core inclusions
 */
$hkymalvexa_core_files = array(
	'db.php', 'signatures.php', 'classifier.php', 'integrity.php',
	'malware-detector.php', 'uploads-analyzer.php', 'config-analyzer.php',
	'persistence.php', 'database-scanner.php', 'engine.php', 'quarantine.php',
	'restorer.php', 'admin.php', 'ajax.php',
);

foreach ( $hkymalvexa_core_files as $hkymalvexa_core_file ) {
	$hkymalvexa_core_path = HKYMALVEXA_PLUGIN_DIR . 'includes/' . $hkymalvexa_core_file;
	if ( file_exists( $hkymalvexa_core_path ) ) {
		require_once $hkymalvexa_core_path;
	}
}

/**
 * Activation Hook
 */
function hkymalvexa_on_activation() {
	if ( function_exists( 'hkymalvexa_install_database_tables' ) ) {
		hkymalvexa_install_database_tables();
	}
}
register_activation_hook( __FILE__, 'hkymalvexa_on_activation' );

/**
 * Deactivation Hook
 */
function hkymalvexa_on_deactivation() {
	wp_clear_scheduled_hook( 'hkymalvexa_scheduled_scan' );
}
register_deactivation_hook( __FILE__, 'hkymalvexa_on_deactivation' );

/**
 * Initialize HKY MalVexa plugin
 */
function hkymalvexa_bootstrap() {
	if ( function_exists( 'hkymalvexa_admin_init' ) ) {
		hkymalvexa_admin_init();
	}
	if ( function_exists( 'hkymalvexa_ajax_init' ) ) {
		hkymalvexa_ajax_init();
	}
}
add_action( 'plugins_loaded', 'hkymalvexa_bootstrap' );

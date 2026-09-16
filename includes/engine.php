<?php
/**
 * HKY MalVexa Procedural Master Scan Engine
 * Chunked batched scanner guaranteeing zero server timeouts on any hosting
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom database queries for security scan batches and findings.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Initialize a new scan job and catalog target files
 */
function hkymalvexa_init_scan( $site_id, $scan_type = 'deep' ) {
	global $wpdb;

	$table_sites = hkymalvexa_get_table( 'sites' );
	$table_scans = hkymalvexa_get_table( 'scans' );

	$site = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_sites WHERE id = %d", $site_id ) );
	if ( ! $site ) {
		$site_id = hkymalvexa_get_current_site_id();
		$site    = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_sites WHERE id = %d", $site_id ) );
	}
	if ( ! $site ) {
		$site = (object) array(
			'id'          => 1,
			'name'        => get_bloginfo( 'name' ) ? get_bloginfo( 'name' ) : 'This WordPress Site',
			'url'         => home_url(),
			'wp_path'     => ABSPATH,
			'access_mode' => 'local',
		);
	}

	// Resolve target site path dynamically
	$scan_path = hkymalvexa_get_site_root( $site );

	// Clean out previous findings for THIS specific site to prevent cross-contamination
	$table_findings = hkymalvexa_get_table( 'findings' );
	$wpdb->delete( $table_findings, array( 'site_id' => $site_id ) );

	// Catalog all target files across whole site
	$files = hkymalvexa_catalog_files( $scan_path );
	$total_files = count( $files );
	$breakdown = hkymalvexa_get_catalog_breakdown( $files );

	// Insert scan record
	$wpdb->insert(
		$table_scans,
		array(
			'site_id'        => $site_id,
			'scan_type'      => sanitize_text_field( $scan_type ),
			'status'         => 'running',
			'total_files'    => $total_files,
			'scanned_files'  => 0,
			'findings_count' => 0,
			'started_at'     => current_time( 'mysql' ),
			'batch_offset'   => 0,
		)
	);

	$scan_id = $wpdb->insert_id;

	// Cache file queue in transient for chunked processing
	set_transient( 'hkymalvexa_file_queue_' . $scan_id, $files, 2 * HOUR_IN_SECONDS );

	// Pre-load official checksums cache
	hkymalvexa_get_core_checksums();

	// Log audit event
	hkymalvexa_log_audit( $site_id, 'start_scan', $site->name, "Started {$scan_type} scan with {$total_files} files cataloged." );

	return array(
		'scan_id'     => $scan_id,
		'total_files' => $total_files,
		'site_name'   => $site->name,
		'breakdown'   => $breakdown,
	);
}

/**
 * Process a single batch/chunk of files
 */
function hkymalvexa_process_batch( $scan_id, $batch_size = 120 ) {
	global $wpdb;

	$table_scans = hkymalvexa_get_table( 'scans' );
	$table_findings = hkymalvexa_get_table( 'findings' );
	$table_sites = hkymalvexa_get_table( 'sites' );

	$scan = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_scans WHERE id = %d", $scan_id ) );
	if ( ! $scan || $scan->status !== 'running' ) {
		return new WP_Error( 'invalid_scan', 'Scan is not running.' );
	}

	$files = get_transient( 'hkymalvexa_file_queue_' . $scan_id );
	if ( false === $files || ! is_array( $files ) ) {
		return new WP_Error( 'missing_queue', 'Scan file queue expired or missing.' );
	}

	$total_files = count( $files );
	$offset = (int) $scan->batch_offset;
	$batch = array_slice( $files, $offset, $batch_size );

	$core_checksums = hkymalvexa_get_core_checksums();

	// Resolve the target site directory
	$site      = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_sites WHERE id = %d", $scan->site_id ) );
	$site_root = hkymalvexa_get_site_root( $site );

	// At the start of the scan (offset === 0), run database, SEO spam, and persistence checks immediately
	if ( $offset === 0 ) {
		$persistence_hits = hkymalvexa_scan_dropins_and_mu( $site_root );
		$cron_hits        = hkymalvexa_scan_cron_jobs( $scan->site_id );
		$db_hits          = hkymalvexa_scan_database( $scan->site_id );

		$initial_checks = array_merge( $persistence_hits, $cron_hits, $db_hits );
		foreach ( $initial_checks as $ic ) {
			$wpdb->insert(
				$table_findings,
				array(
					'scan_id'            => $scan_id,
					'site_id'            => $scan->site_id,
					'severity'           => $ic['severity'],
					'classification'     => $ic['classification'],
					'confidence'         => $ic['confidence'],
					'category'           => $ic['category'],
					'file_path'          => $ic['file_path'],
					'line_number'        => $ic['line_number'],
					'evidence'           => $ic['evidence'],
					'description'        => $ic['description'],
					'recommended_action' => $ic['recommended_action'],
					'status'             => 'new',
					'created_at'         => current_time( 'mysql' ),
				)
			);
		}
	}

	$new_findings = array();
	$current_folder = '';
	if ( ! empty( $batch ) ) {
		$first_file = $batch[0];
		$first_dir = dirname( $first_file );
		$current_folder = ( $first_dir === '.' ) ? 'root' : $first_dir;
	}

	foreach ( $batch as $file_rel ) {
		$full_path = $site_root . '/' . ltrim( $file_rel, '/\\' );
		$classification = hkymalvexa_classify_file( $file_rel );
		$is_verified_clean_core = false;

		// 1. Core Integrity
		if ( $classification === 'CORE' ) {
			if ( ! empty( $core_checksums ) ) {
				$check = hkymalvexa_verify_core_file( $file_rel, $full_path, $core_checksums );
				if ( $check ) {
					if ( $check['status'] === 'clean' ) {
						$is_verified_clean_core = true;
					} else {
						$new_findings[] = array(
							'scan_id'            => $scan_id,
							'site_id'            => $scan->site_id,
							'severity'           => $check['severity'],
							'classification'     => 'malicious',
							'confidence'         => $check['confidence'],
							'category'           => 'core_integrity',
							'file_path'          => $file_rel,
							'line_number'        => 1,
							'evidence'           => 'Core Checksum Hash Mismatch / Extraneous file',
							'description'        => $check['description'],
							'recommended_action' => $check['action'],
						);
					}
				}
			} else {
				// If official checksums could not be fetched from network, treat core directories as trusted
				$is_verified_clean_core = true;
			}
		}

		// 2. Uploads analysis
		if ( $classification === 'UPLOAD' ) {
			$upload_issues = hkymalvexa_analyze_upload_file( $full_path, $file_rel );
			if ( ! empty( $upload_issues ) ) {
				foreach ( $upload_issues as $ui ) {
					$ui['scan_id'] = $scan_id;
					$ui['site_id'] = $scan->site_id;
					$new_findings[] = $ui;
				}
			}
		}

		// 3. Config forensics
		if ( $classification === 'CONFIG' ) {
			$config_issues = hkymalvexa_analyze_config_file( $full_path, $file_rel );
			if ( ! empty( $config_issues ) ) {
				foreach ( $config_issues as $ci ) {
					$ci['scan_id'] = $scan_id;
					$ci['site_id'] = $scan->site_id;
					$new_findings[] = $ci;
				}
			}
		}

		// 4. PHP static malware detection (Runs on all non-core files, or modified core files)
		if ( ! $is_verified_clean_core ) {
			$malware_hits = hkymalvexa_scan_file_malware( $full_path, $file_rel );
			if ( ! empty( $malware_hits ) ) {
				foreach ( $malware_hits as $mh ) {
					$mh['scan_id'] = $scan_id;
					$mh['site_id'] = $scan->site_id;
					$new_findings[] = $mh;
				}
			}
		}
	}

	// Insert batch findings
	foreach ( $new_findings as $f ) {
		$wpdb->insert(
			$table_findings,
			array(
				'scan_id'            => $f['scan_id'],
				'site_id'            => $f['site_id'],
				'severity'           => $f['severity'],
				'classification'     => $f['classification'],
				'confidence'         => $f['confidence'],
				'category'           => $f['category'],
				'file_path'          => $f['file_path'],
				'line_number'        => $f['line_number'],
				'evidence'           => $f['evidence'],
				'description'        => $f['description'],
				'recommended_action' => $f['recommended_action'],
				'status'             => 'new',
				'created_at'         => current_time( 'mysql' ),
			)
		);
	}

	$new_offset = $offset + count( $batch );
	$total_scanned = min( $new_offset, $total_files );
	$current_findings_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table_findings WHERE scan_id = %d", $scan_id ) );
	$is_completed = ( $new_offset >= $total_files );

	$wpdb->update(
		$table_scans,
		array(
			'batch_offset'   => $new_offset,
			'scanned_files'  => $total_scanned,
			'findings_count' => $current_findings_count,
		),
		array( 'id' => $scan_id )
	);

	if ( $is_completed ) {
		hkymalvexa_finish_scan( $scan_id );
		$current_findings_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table_findings WHERE scan_id = %d", $scan_id ) );
	}

	$progress_pct = ( $total_files > 0 ) ? round( ( $total_scanned / $total_files ) * 100, 1 ) : 100;

	return array(
		'scan_id'        => $scan_id,
		'scanned_files'  => $total_scanned,
		'total_files'    => $total_files,
		'percentage'     => $progress_pct,
		'findings_count' => $current_findings_count,
		'is_completed'   => $is_completed,
		'current_folder' => $current_folder,
	);
}

/**
 * Finalize scan: run persistence/database checks and update health status
 */
function hkymalvexa_finish_scan( $scan_id ) {
	global $wpdb;

	$table_scans = hkymalvexa_get_table( 'scans' );
	$table_sites = hkymalvexa_get_table( 'sites' );
	$table_findings = hkymalvexa_get_table( 'findings' );

	$scan = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_scans WHERE id = %d", $scan_id ) );
	if ( ! $scan ) {
		return;
	}

	// Check if initial database & persistence checks already ran at offset 0
	$db_like = $wpdb->esc_like( 'database:' ) . '%';
	$already_ran_db = (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(*) FROM {$table_findings} WHERE scan_id = %d AND (category IN ('wpcode_snippet', 'db_option_injection', 'seo_spam_injection', 'persistence_dropin', 'persistence_mu') OR file_path LIKE %s)",
			$scan_id,
			$db_like
		)
	);
	if ( $already_ran_db === 0 ) {
		$site_root = hkymalvexa_get_site_root( $scan->site_id );
		$persistence_hits = hkymalvexa_scan_dropins_and_mu( $site_root );
		$cron_hits = hkymalvexa_scan_cron_jobs( $scan->site_id );
		$db_hits = hkymalvexa_scan_database( $scan->site_id );

		$extra_findings = array_merge( $persistence_hits, $cron_hits, $db_hits );

		foreach ( $extra_findings as $ef ) {
			$wpdb->insert(
				$table_findings,
				array(
					'scan_id'            => $scan_id,
					'site_id'            => $scan->site_id,
					'severity'           => $ef['severity'],
					'classification'     => $ef['classification'],
					'confidence'         => $ef['confidence'],
					'category'           => $ef['category'],
					'file_path'          => $ef['file_path'],
					'line_number'        => $ef['line_number'],
					'evidence'           => $ef['evidence'],
					'description'        => $ef['description'],
					'recommended_action' => $ef['recommended_action'],
					'status'             => 'new',
					'created_at'         => current_time( 'mysql' ),
				)
			);
		}
	}

	$final_findings_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table_findings WHERE scan_id = %d", $scan_id ) );

	$has_critical = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table_findings WHERE scan_id = %d AND severity = 'critical'", $scan_id ) );
	$health_status = ( $has_critical > 0 ) ? 'compromised' : ( ( $final_findings_count > 0 ) ? 'warning' : 'healthy' );

	// Complete scan record
	$wpdb->update(
		$table_scans,
		array(
			'status'         => 'completed',
			'findings_count' => $final_findings_count,
			'completed_at'   => current_time( 'mysql' ),
		),
		array( 'id' => $scan_id )
	);

	// Update site record
	$wpdb->update(
		$table_sites,
		array(
			'last_scan'     => current_time( 'mysql' ),
			'health_status' => $health_status,
		),
		array( 'id' => $scan->site_id )
	);

	// Clean up transient queue
	delete_transient( 'hkymalvexa_file_queue_' . $scan_id );

	// Log audit
	hkymalvexa_log_audit( $scan->site_id, 'complete_scan', "Scan #{$scan_id}", "Completed scan with {$final_findings_count} findings. Health: {$health_status}." );
}

/**
 * Catalog all files relative to WordPress root
 * Recursively scans every folder: plugins, themes, uploads, core, and custom dirs
 */
function hkymalvexa_catalog_files( $base_dir ) {
	$file_list = array();
	if ( ! is_dir( $base_dir ) ) {
		return $file_list;
	}

	$base_dir = rtrim( str_replace( '\\', '/', $base_dir ), '/' );

	try {
		$dir_iterator = new RecursiveDirectoryIterator(
			$base_dir,
			FilesystemIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS
		);
		$iterator = new RecursiveIteratorIterator( $dir_iterator, RecursiveIteratorIterator::SELF_FIRST );

		foreach ( $iterator as $item ) {
			try {
				if ( $item->isFile() ) {
					$path = str_replace( '\\', '/', $item->getPathname() );
					if ( strpos( $path, 'hky-malvexa-quarantine' ) !== false || strpos( $path, 'hkymalvexa-quarantine' ) !== false || strpos( $path, 'hky-malvexa' ) !== false || strpos( $path, 'hkymalvexa' ) !== false || strpos( $path, '.git' ) !== false ) {
						continue;
					}
					$rel = ltrim( substr( $path, strlen( $base_dir ) ), '/\\' );
					$file_list[] = str_replace( '\\', '/', $rel );
				}
			} catch ( Exception $e ) {
				// Continue if individual item is restricted
				continue;
			}
		}
	} catch ( Exception $e ) {
		// Fallback simple directory scan if recursive iterator fails
	}

	return $file_list;
}

/**
 * Summarize file counts by folder category for transparent terminal logs
 */
function hkymalvexa_get_catalog_breakdown( $files ) {
	$stats = array(
		'plugins' => 0,
		'themes'  => 0,
		'uploads' => 0,
		'core'    => 0,
		'custom'  => 0,
	);

	foreach ( $files as $f ) {
		if ( strpos( $f, 'wp-content/plugins/' ) === 0 || strpos( $f, 'wp-content/mu-plugins/' ) === 0 ) {
			$stats['plugins']++;
		} elseif ( strpos( $f, 'wp-content/themes/' ) === 0 ) {
			$stats['themes']++;
		} elseif ( strpos( $f, 'wp-content/uploads/' ) === 0 ) {
			$stats['uploads']++;
		} elseif ( strpos( $f, 'wp-admin/' ) === 0 || strpos( $f, 'wp-includes/' ) === 0 || in_array( $f, array( 'index.php', 'wp-login.php', 'wp-settings.php', 'wp-load.php', 'wp-cron.php', 'xmlrpc.php' ), true ) ) {
			$stats['core']++;
		} else {
			$stats['custom']++;
		}
	}

	return $stats;
}

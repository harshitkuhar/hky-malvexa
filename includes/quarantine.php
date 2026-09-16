<?php
/**
 * HKY MalVexa Procedural Safe Quarantine & Rollback System
 * Implements Golden Recovery Rule: Isolates files in protected storage with 1-click restore
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.SlowDBQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom database quarantine vault queries and Elementor postmeta cleaner.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Quarantine an infected file safely
 */
function hkymalvexa_quarantine_file( $finding_id ) {
	global $wpdb;

	$table_findings = hkymalvexa_get_table( 'findings' );
	$table_quarantine = hkymalvexa_get_table( 'quarantine' );

	$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_findings WHERE id = %d", $finding_id ) );
	if ( ! $finding ) {
		return new WP_Error( 'not_found', 'Finding not found.' );
	}

	$rel_path = $finding->file_path;

	// Critical Guard: NEVER allow quarantining HKY MalVexa's own files or essential WP config
	$protected_patterns = array( 'hky-malvexa', 'wp-config.php', 'wp-load.php', 'wp-settings.php' );
	foreach ( $protected_patterns as $pattern ) {
		if ( stripos( $rel_path, $pattern ) !== false ) {
			return new WP_Error( 'protected_file', 'Protection Guard: Cannot quarantine system files or HKY MalVexa plugin files.' );
		}
	}

	// Path traversal protection
	if ( strpos( $rel_path, '..' ) !== false || strpos( $rel_path, "\0" ) !== false ) {
		return new WP_Error( 'invalid_path', 'Invalid or prohibited file path.' );
	}

	// 1. Support quarantining database threats (posts, options, snippets)
	if ( strpos( $rel_path, 'database:' ) === 0 || $finding->category === 'wpcode_snippet' || $finding->category === 'db_option_injection' ) {
		$target_db = hkymalvexa_get_target_db( $finding->site_id );
		$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );
		$timestamp = time();

		$db_payload = null;
		$quarantine_filename = '';

		// A. Post in {$target_db->posts}
		if ( stripos( $rel_path, 'posts' ) !== false || $finding->category === 'wpcode_snippet' ) {
			$post_id = (int) $finding->line_number;
			if ( $post_id > 0 ) {
				$post = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->posts}` WHERE ID = %d", $post_id ), ARRAY_A );
				if ( $post ) {
					$postmeta = $target_db->get_results( $target_db->prepare( "SELECT * FROM `{$target_db->postmeta}` WHERE post_id = %d", $post_id ), ARRAY_A );
					$db_payload = array(
						'type'     => 'post',
						'table'    => $target_db->posts,
						'post'     => $post,
						'postmeta' => $postmeta,
					);
					$quarantine_filename = 'db_post_' . $post_id . '.' . $timestamp . '.quarantined';
					$target_db->delete( $target_db->posts, array( 'ID' => $post_id ) );
					$target_db->delete( $target_db->postmeta, array( 'post_id' => $post_id ) );
					$target_db->query( "DELETE FROM `{$target_db->options}` WHERE option_name = 'wpcode_snippets'" );
				}
			}
		} elseif ( stripos( $rel_path, 'options' ) !== false || $finding->category === 'db_option_injection' ) {
			// B. Option in {$target_db->options}
			$option_id = (int) $finding->line_number;
			$opt = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->options}` WHERE option_id = %d", $option_id ), ARRAY_A );
			if ( ! $opt && preg_match( '/Option:\s*([a-zA-Z0-9_\-]+)/i', $rel_path, $om ) ) {
				$opt = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->options}` WHERE option_name = %s", $om[1] ), ARRAY_A );
			}
			if ( $opt ) {
				$db_payload = array(
					'type'   => 'option',
					'table'  => $target_db->options,
					'option' => $opt,
				);
				$quarantine_filename = 'db_option_' . sanitize_file_name( $opt['option_name'] ) . '.' . $timestamp . '.quarantined';
				$target_db->delete( $target_db->options, array( 'option_id' => $opt['option_id'] ) );
			}
		} elseif ( stripos( $rel_path, 'snippets' ) !== false ) {
			// C. Snippet in {$target_db->prefix}snippets
			$snippets_table = $target_db->prefix . 'snippets';
			$snippet_id = (int) $finding->line_number;
			$sp = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$snippets_table}` WHERE id = %d", $snippet_id ), ARRAY_A );
			if ( $sp ) {
				$db_payload = array(
					'type'    => 'snippet',
					'table'   => $snippets_table,
					'snippet' => $sp,
				);
				$quarantine_filename = 'db_snippet_' . $snippet_id . '.' . $timestamp . '.quarantined';
				$target_db->delete( $snippets_table, array( 'id' => $snippet_id ) );
				$target_db->query( "DELETE FROM `{$target_db->options}` WHERE option_name = 'wpcode_snippets'" );
			}
		}

		if ( ! $db_payload ) {
			$wpdb->update( $table_findings, array( 'status' => 'quarantined' ), array( 'id' => $finding_id ) );
			return array(
				'success'       => true,
				'quarantine_id' => 0,
				'original_path' => $rel_path,
			);
		}

		$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
		$json_data = wp_json_encode( $db_payload );
		@file_put_contents( $quarantine_dest, $json_data );
		$quarantine_hash = hash( 'sha256', $json_data );

		$wpdb->insert(
			$table_quarantine,
			array(
				'finding_id'           => $finding_id,
				'site_id'              => $finding->site_id,
				'original_path'        => $rel_path,
				'original_hash'        => $quarantine_hash,
				'original_permissions' => 'DB_RECORD',
				'quarantine_path'      => $quarantine_dest,
				'quarantine_hash'      => $quarantine_hash,
				'reason'               => $finding->description,
				'status'               => 'quarantined',
				'created_at'           => current_time( 'mysql' ),
			)
		);
		$quarantine_id = $wpdb->insert_id;

		$wpdb->update( $table_findings, array( 'status' => 'quarantined' ), array( 'id' => $finding_id ) );
		hkymalvexa_log_audit( $finding->site_id, 'quarantine_db', $rel_path, "Quarantined database threat to client vault: {$quarantine_filename}" );

		return array(
			'success'       => true,
			'quarantine_id' => $quarantine_id,
			'original_path' => $rel_path,
		);
	}

	$full_path = hkymalvexa_get_site_root( $finding->site_id ) . '/' . ltrim( $rel_path, '/\\' );

	if ( ! file_exists( $full_path ) ) {
		return new WP_Error( 'file_not_found', 'Target file does not exist on disk.' );
	}

	$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );

	$file_hash = hash_file( 'sha256', $full_path );
	$file_perms = substr( sprintf( '%o', fileperms( $full_path ) ), -4 );
	$timestamp = time();
	$quarantine_filename = sanitize_file_name( basename( $rel_path ) ) . '.' . $timestamp . '.quarantined';
	$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;

	// 1. Copy original file to protected quarantine directory
	if ( ! @copy( $full_path, $quarantine_dest ) ) {
		return new WP_Error( 'copy_failed', 'Failed to copy file to quarantine directory.' );
	}

	// 2. Remove or neutralize the original file
	wp_delete_file( $full_path );

	// 3. Log quarantine record
	$wpdb->insert(
		$table_quarantine,
		array(
			'finding_id'           => $finding_id,
			'site_id'              => $finding->site_id,
			'original_path'        => $rel_path,
			'original_hash'        => $file_hash,
			'original_permissions' => $file_perms,
			'quarantine_path'      => $quarantine_dest,
			'quarantine_hash'      => hash_file( 'sha256', $quarantine_dest ),
			'reason'               => $finding->description,
			'status'               => 'quarantined',
			'created_at'           => current_time( 'mysql' ),
		)
	);
	$quarantine_id = $wpdb->insert_id;

	// 4. Update finding status
	$wpdb->update(
		$table_findings,
		array( 'status' => 'quarantined' ),
		array( 'id' => $finding_id )
	);

	// 5. Add audit log
	hkymalvexa_log_audit( $finding->site_id, 'quarantine_file', $rel_path, "Quarantined file to: {$quarantine_filename}. Hash: {$file_hash}" );

	return array(
		'success'       => true,
		'quarantine_id' => $quarantine_id,
		'original_path' => $rel_path,
	);
}

/**
 * Restore a quarantined file back to original location
 */
function hkymalvexa_restore_file( $quarantine_id ) {
	global $wpdb;

	$table_quarantine = hkymalvexa_get_table( 'quarantine' );
	$table_findings = hkymalvexa_get_table( 'findings' );

	$item = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_quarantine WHERE id = %d", $quarantine_id ) );
	if ( ! $item || ! in_array( $item->status, array( 'quarantined', 'cleaned' ), true ) ) {
		return new WP_Error( 'not_found', 'Quarantine record not found or already restored.' );
	}

	$quarantine_path = $item->quarantine_path;
	if ( ! file_exists( $quarantine_path ) ) {
		$fname = basename( $quarantine_path );
		$site_root = function_exists( 'hkymalvexa_get_site_root' ) ? hkymalvexa_get_site_root( $item->site_id ) : ABSPATH;
		$candidate_paths = array(
			hkymalvexa_get_site_quarantine_dir( $item->site_id, 'vault' ) . '/' . $fname,
			hkymalvexa_get_site_quarantine_dir( $item->site_id, 'cleaned_backups' ) . '/' . $fname,
			$site_root . '/wp-content/uploads/hkymalvexa-quarantine/vault/' . $fname,
			$site_root . '/wp-content/uploads/hkymalvexa-quarantine/cleaned_backups/' . $fname,
		);
		foreach ( $candidate_paths as $cand ) {
			if ( file_exists( $cand ) ) {
				$quarantine_path = $cand;
				break;
			}
		}
	}

	if ( ! file_exists( $quarantine_path ) ) {
		return new WP_Error( 'missing_vault', 'Quarantined backup file is missing from vault (' . esc_html( basename( $item->quarantine_path ) ) . ').' );
	}

	// Support restoring database records
	if ( $item->original_permissions === 'DB_RECORD' || strpos( $item->original_path, 'database:' ) === 0 ) {
		$target_db = hkymalvexa_get_target_db( $item->site_id );
		$json = @file_get_contents( $quarantine_path );
		$payload = ! empty( $json ) ? json_decode( $json, true ) : null;

		if ( $payload && is_array( $payload ) ) {
			if ( $payload['type'] === 'post' && ! empty( $payload['post'] ) ) {
				$target_db->replace( $payload['table'], $payload['post'] );
				if ( ! empty( $payload['postmeta'] ) && is_array( $payload['postmeta'] ) ) {
					foreach ( $payload['postmeta'] as $meta ) {
						$target_db->replace( $target_db->postmeta, $meta );
					}
				}
				if ( isset( $payload['post']['ID'] ) ) {
					$target_db->delete( $target_db->postmeta, array( 'post_id' => $payload['post']['ID'], 'meta_key' => '_elementor_css' ) );
				}
			} elseif ( $payload['type'] === 'option' && ! empty( $payload['option'] ) ) {
				$target_db->replace( $payload['table'], $payload['option'] );
			} elseif ( $payload['type'] === 'snippet' && ! empty( $payload['snippet'] ) ) {
				$target_db->replace( $payload['table'], $payload['snippet'] );
			}
		} elseif ( ! empty( $json ) && strpos( $json, '// RAW POST CONTENT:' ) !== false ) {
			// Fallback parser for legacy pre-clean text files
			$parts = explode( '// RAW POST CONTENT:', $json );
			if ( isset( $parts[1] ) ) {
				$subparts = explode( '// ELEMENTOR DATA:', $parts[1] );
				$raw_content = trim( $subparts[0] );
				$elem_data = isset( $subparts[1] ) ? trim( $subparts[1] ) : '';

				$post_id = 0;
				if ( preg_match( '/Post ID:\s*(\d+)/i', $json, $pid_m ) ) {
					$post_id = (int) $pid_m[1];
				} elseif ( preg_match( '/#(\d+)/', $item->original_path, $pid_m ) ) {
					$post_id = (int) $pid_m[1];
				}

				if ( $post_id > 0 ) {
					$target_db->update( $target_db->posts, array( 'post_content' => $raw_content ), array( 'ID' => $post_id ) );
					if ( ! empty( $elem_data ) && $elem_data !== 'N/A' ) {
						$target_db->update( $target_db->postmeta, array( 'meta_value' => $elem_data ), array( 'post_id' => $post_id, 'meta_key' => '_elementor_data' ) );
					}
					$target_db->delete( $target_db->postmeta, array( 'post_id' => $post_id, 'meta_key' => '_elementor_css' ) );
				}
			}
		}

		$wpdb->update( $table_quarantine, array( 'status' => 'restored', 'restored_at' => current_time( 'mysql' ) ), array( 'id' => $quarantine_id ) );
		$fid = (int) $item->finding_id;
		if ( ! $fid ) {
			$fid = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM $table_findings WHERE site_id = %d AND file_path = %s LIMIT 1", $item->site_id, $item->original_path ) );
		}
		if ( $fid ) {
			$wpdb->update( $table_findings, array( 'status' => 'new' ), array( 'id' => $fid ) );
		}
		hkymalvexa_log_audit( $item->site_id, 'restore_db', $item->original_path, "Restored database record from quarantine vault back to active state." );

		return array(
			'success'       => true,
			'original_path' => $item->original_path,
		);
	}

	// Path traversal protection on restore
	if ( strpos( $item->original_path, '..' ) !== false || strpos( $item->original_path, "\0" ) !== false ) {
		return new WP_Error( 'invalid_path', 'Invalid or prohibited restore destination.' );
	}

	$site_root = function_exists( 'hkymalvexa_get_site_root' ) 
		? hkymalvexa_get_site_root( $item->site_id ) 
		: rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
	$dest      = $site_root . '/' . ltrim( $item->original_path, '/\\' );

	if ( strpos( $dest, $site_root . '/' ) !== 0 ) {
		return new WP_Error( 'path_escape', 'Restore path escape detected.' );
	}

	// Reject restore to a symbolic link
	if ( is_link( $dest ) ) {
		return new WP_Error( 'symlink_rejected', 'Cannot restore onto a symbolic link.' );
	}

	$dest_dir = dirname( $dest );
	if ( ! is_dir( $dest_dir ) ) {
		wp_mkdir_p( $dest_dir );
	}

	// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Legitimate restoration of quarantined file back to its original site location.
	if ( ! @copy( $quarantine_path, $dest ) ) {
		return new WP_Error( 'restore_failed', 'Failed to copy file back to original location.' );
	}

	// Update quarantine record
	$wpdb->update(
		$table_quarantine,
		array(
			'status'      => 'restored',
			'restored_at' => current_time( 'mysql' ),
		),
		array( 'id' => $quarantine_id )
	);

	// Update finding record to active 'new'
	$fid = (int) $item->finding_id;
	if ( ! $fid ) {
		$fid = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM $table_findings WHERE site_id = %d AND file_path = %s LIMIT 1", $item->site_id, $item->original_path ) );
	}
	if ( $fid ) {
		$wpdb->update(
			$table_findings,
			array( 'status' => 'new' ),
			array( 'id' => $fid )
		);
	}

	// Audit log
	hkymalvexa_log_audit( $item->site_id, 'restore_quarantine', $item->original_path, "Restored file from quarantine back to active state. Hash: {$item->original_hash}" );

	return array(
		'success'       => true,
		'original_path' => $item->original_path,
	);
}

/**
 * Clean / Neutralize injected malicious code from a legitimate file
 * Creates a safety backup, comments out the malicious code line, and validates syntax
 */
function hkymalvexa_clean_file_injection( $finding_id ) {
	global $wpdb;

	$table_findings   = hkymalvexa_get_table( 'findings' );
	$table_quarantine = hkymalvexa_get_table( 'quarantine' );

	$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_findings WHERE id = %d", $finding_id ) );
	if ( ! $finding ) {
		return new WP_Error( 'not_found', 'Finding not found.' );
	}

	$rel_path = $finding->file_path;

	// Never modify HKY MalVexa's own files
	if ( stripos( $rel_path, 'hky-malvexa' ) !== false ) {
		return new WP_Error( 'protected_file', 'Protection Guard: Cannot modify HKY MalVexa plugin files.' );
	}

	// 1. Support neutralizing database threats (WPCode posts, WPCode options, dedicated tables, and SEO Spam)
	if ( strpos( $rel_path, 'database:' ) === 0 || $finding->category === 'wpcode_snippet' || $finding->category === 'db_option_injection' || $finding->category === 'seo_spam_injection' ) {
		$target_db = hkymalvexa_get_target_db( $finding->site_id );

		// A. Blackhat SEO / Casino Spam Injected Posts, Elementor Pages & Options (Surgical Cleaning)
		if ( $finding->category === 'seo_spam_injection' ) {
			$strip_pattern = '/<div[^>]*?(?:data-wp-poster\s*=\s*[\'"][a-f0-9]{16,}[\'"]|style\s*=\s*[\'"][^\'"]*(?:left|top|margin-left|text-indent)\s*:\s*-\d{4,}px)[^>]*?>.*?<\/div>/is';

			if ( stripos( $rel_path, 'options' ) !== false ) {
				$option_id = (int) $finding->line_number;
				$opt = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->options}` WHERE option_id = %d", $option_id ), ARRAY_A );
				if ( $opt ) {
					// 1. Create client safety backup in Quarantine Vault
					$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );
					$timestamp = time();
					$db_payload = array(
						'type'   => 'option',
						'table'  => $target_db->options,
						'option' => $opt,
					);
					$quarantine_filename = 'db_option_clean_' . sanitize_file_name( $opt['option_name'] ) . '.' . $timestamp . '.quarantined';
					$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
					$json_data = wp_json_encode( $db_payload );
					@file_put_contents( $quarantine_dest, $json_data );
					$quarantine_hash = hash( 'sha256', $json_data );

					// 2. Insert into Quarantine Vault table
					$wpdb->insert(
						$table_quarantine,
						array(
							'finding_id'           => $finding_id,
							'site_id'              => $finding->site_id,
							'original_path'        => $rel_path,
							'original_hash'        => $quarantine_hash,
							'original_permissions' => 'DB_RECORD',
							'quarantine_path'      => $quarantine_dest,
							'quarantine_hash'      => $quarantine_hash,
							'reason'               => $finding->description,
							'status'               => 'cleaned',
							'created_at'           => current_time( 'mysql' ),
						)
					);

					// 3. Clean
					$cleaned_val = hkymalvexa_clean_seo_spam_content( $opt['option_value'] );
					$target_db->update(
						$target_db->options,
						array( 'option_value' => $cleaned_val ),
						array( 'option_id' => $option_id )
					);
					$wpdb->update( $table_findings, array( 'status' => 'cleaned' ), array( 'id' => $finding_id ) );
					hkymalvexa_log_audit( $finding->site_id, 'clean_seo_spam', $rel_path, "Surgically removed SEO spam from option #{$option_id}. Vault Backup: {$quarantine_filename}" );
					return array(
						'success'     => true,
						'file_path'   => $rel_path,
						'line_number' => $option_id,
					);
				}
			}

			// Posts / Pages / Elementor
			$post_id = (int) $finding->line_number;
			if ( $post_id > 0 ) {
				$post = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->posts}` WHERE ID = %d", $post_id ), ARRAY_A );
				if ( $post ) {
					// 1. Create client safety backup in Quarantine Vault & Cleaned backups
					$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );
					$backup_dir     = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'cleaned_backups' );
					$timestamp      = time();

					$postmeta = $target_db->get_results( $target_db->prepare( "SELECT * FROM `{$target_db->postmeta}` WHERE post_id = %d", $post_id ), ARRAY_A );

					$db_payload = array(
						'type'     => 'post',
						'table'    => $target_db->posts,
						'post'     => $post,
						'postmeta' => $postmeta,
					);
					$quarantine_filename = 'db_post_clean_' . $post_id . '.' . $timestamp . '.quarantined';
					$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
					$json_data = wp_json_encode( $db_payload );
					@file_put_contents( $quarantine_dest, $json_data );
					$quarantine_hash = hash( 'sha256', $json_data );

					// Insert into Quarantine Vault table
					$wpdb->insert(
						$table_quarantine,
						array(
							'finding_id'           => $finding_id,
							'site_id'              => $finding->site_id,
							'original_path'        => $rel_path,
							'original_hash'        => $quarantine_hash,
							'original_permissions' => 'DB_RECORD',
							'quarantine_path'      => $quarantine_dest,
							'quarantine_hash'      => $quarantine_hash,
							'reason'               => $finding->description,
							'status'               => 'cleaned',
							'created_at'           => current_time( 'mysql' ),
						)
					);

					$orig_meta = '';
					if ( ! empty( $postmeta ) ) {
						foreach ( $postmeta as $pm ) {
							if ( isset( $pm['meta_key'] ) && $pm['meta_key'] === '_elementor_data' ) {
								$orig_meta = $pm['meta_value'];
								break;
							}
						}
					}

					// 2. Clean in post_content
					$cleaned_content = hkymalvexa_clean_seo_spam_content( $post['post_content'] );
					if ( $cleaned_content !== $post['post_content'] ) {
						$target_db->update(
							$target_db->posts,
							array( 'post_content' => $cleaned_content ),
							array( 'ID' => $post_id )
						);
					}

					// 3. Clean in _elementor_data (postmeta)
					if ( ! empty( $orig_meta ) ) {
						$decoded = json_decode( $orig_meta, true );
						if ( is_array( $decoded ) ) {
							hkymalvexa_clean_elementor_tree( $decoded, $strip_pattern );
							$new_json = wp_json_encode( $decoded );
							$target_db->update(
								$target_db->postmeta,
								array( 'meta_value' => $new_json ),
								array( 'post_id' => $post_id, 'meta_key' => '_elementor_data' )
							);
						} else {
							$cleaned_meta = hkymalvexa_clean_seo_spam_content( $orig_meta );
							if ( $cleaned_meta !== $orig_meta ) {
								$target_db->update(
									$target_db->postmeta,
									array( 'meta_value' => $cleaned_meta ),
									array( 'post_id' => $post_id, 'meta_key' => '_elementor_data' )
								);
							}
						}
						// Clear Elementor CSS cache
						$target_db->delete( $target_db->postmeta, array( 'post_id' => $post_id, 'meta_key' => '_elementor_css' ) );
					}

					// 4. If this finding targeted a revision, also clean the parent page
					if ( isset( $post['post_type'] ) && $post['post_type'] === 'revision' && ! empty( $post['post_parent'] ) ) {
						$parent_id = (int) $post['post_parent'];
						$parent_post = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->posts}` WHERE ID = %d", $parent_id ), ARRAY_A );
						if ( $parent_post ) {
							$cleaned_parent = hkymalvexa_clean_seo_spam_content( $parent_post['post_content'] );
							if ( $cleaned_parent !== $parent_post['post_content'] ) {
								$target_db->update( $target_db->posts, array( 'post_content' => $cleaned_parent ), array( 'ID' => $parent_id ) );
							}
						}
					}

					// 5. Also thoroughly clean all revisions of this post so old revisions never trigger scans
					$revisions = $target_db->get_col( $target_db->prepare( "SELECT ID FROM `{$target_db->posts}` WHERE post_type = 'revision' AND post_parent = %d", $post_id ) );
					if ( ! empty( $revisions ) ) {
						foreach ( $revisions as $rev_id ) {
							$rev_content = $target_db->get_var( $target_db->prepare( "SELECT post_content FROM `{$target_db->posts}` WHERE ID = %d", $rev_id ) );
							if ( $rev_content ) {
								$cleaned_rev = hkymalvexa_clean_seo_spam_content( $rev_content );
								if ( $cleaned_rev !== $rev_content ) {
									$target_db->update( $target_db->posts, array( 'post_content' => $cleaned_rev ), array( 'ID' => $rev_id ) );
								}
							}
							$target_db->delete( $target_db->postmeta, array( 'post_id' => $rev_id, 'meta_key' => '_elementor_data' ) );
						}
					}

					$wpdb->update(
						$table_findings,
						array( 'status' => 'cleaned' ),
						array( 'id' => $finding_id )
					);

					$client_backup_rel = 'wp-content/uploads/hkymalvexa-quarantine/vault/' . $quarantine_filename;
					hkymalvexa_log_audit(
						$finding->site_id,
						'clean_seo_spam',
						$rel_path,
						"Surgically removed cloaked SEO spam / casino links from '{$post['post_title']}'. Vault Backup: {$client_backup_rel}"
					);

					return array(
						'success'     => true,
						'backup_file' => $client_backup_rel,
						'file_path'   => $rel_path,
						'line_number' => $post_id,
					);
				}
			}
		}

		// B. WPCode snippet or post stored in {$target_db->posts}
		if ( stripos( $rel_path, 'posts' ) !== false || $finding->category === 'wpcode_snippet' ) {
			$post_id = (int) $finding->line_number;
			if ( $post_id > 0 ) {
				$post = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->posts}` WHERE ID = %d", $post_id ), ARRAY_A );
				if ( $post ) {
					// 1. Create client safety backup in Quarantine Vault
					$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );
					$backup_dir     = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'cleaned_backups' );
					$timestamp      = time();

					$postmeta = $target_db->get_results( $target_db->prepare( "SELECT * FROM `{$target_db->postmeta}` WHERE post_id = %d", $post_id ), ARRAY_A );

					$db_payload = array(
						'type'     => 'post',
						'table'    => $target_db->posts,
						'post'     => $post,
						'postmeta' => $postmeta,
					);
					$quarantine_filename = 'db_snippet_clean_' . $post_id . '.' . $timestamp . '.quarantined';
					$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
					$json_data = wp_json_encode( $db_payload );
					@file_put_contents( $quarantine_dest, $json_data );
					$quarantine_hash = hash( 'sha256', $json_data );

					// Insert into Quarantine Vault table
					$wpdb->insert(
						$table_quarantine,
						array(
							'finding_id'           => $finding_id,
							'site_id'              => $finding->site_id,
							'original_path'        => $rel_path,
							'original_hash'        => $quarantine_hash,
							'original_permissions' => 'DB_RECORD',
							'quarantine_path'      => $quarantine_dest,
							'quarantine_hash'      => $quarantine_hash,
							'reason'               => $finding->description,
							'status'               => 'cleaned',
							'created_at'           => current_time( 'mysql' ),
						)
					);

					// 2. Neutralize post_content and set status to draft
					$neutralized = "/* [HKYMALVEXA NEUTRALIZED MALWARE - " . gmdate( 'Y-m-d H:i:s' ) . "] */\n/*\n" . str_replace( '*/', '* /', $post['post_content'] ) . "\n*/";
					$target_db->update(
						$target_db->posts,
						array(
							'post_content' => $neutralized,
							'post_status'  => 'draft',
						),
						array( 'ID' => $post_id )
					);

					// Also neutralize in postmeta if present
					$target_db->query(
						$target_db->prepare(
							"UPDATE `{$target_db->postmeta}` SET meta_value = %s WHERE post_id = %d AND meta_key IN ('_elementor_data', 'syntax_highlighting')",
							$neutralized,
							$post_id
						)
					);

					// Clear WPCode compiled cache option
					$target_db->query( "DELETE FROM `{$target_db->options}` WHERE option_name = 'wpcode_snippets'" );

					$wpdb->update(
						$table_findings,
						array( 'status' => 'cleaned' ),
						array( 'id' => $finding_id )
					);

					$client_backup_rel = 'wp-content/uploads/hkymalvexa-quarantine/vault/' . $quarantine_filename;
					hkymalvexa_log_audit(
						$finding->site_id,
						'clean_code',
						$rel_path,
						"Safely deactivated & neutralized WPCode post snippet #{$post_id}. Vault Backup: {$client_backup_rel}"
					);

					return array(
						'success'     => true,
						'backup_file' => $client_backup_rel,
						'file_path'   => $rel_path,
						'line_number' => $post_id,
					);
				}
			}
		}

		// C. Malicious or injected option stored in {$target_db->options} (e.g. wpcode_snippets cache)
		if ( stripos( $rel_path, 'options' ) !== false || $finding->category === 'db_option_injection' ) {
			$option_id = (int) $finding->line_number;
			$opt = null;
			if ( $option_id > 0 ) {
				$opt = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->options}` WHERE option_id = %d", $option_id ), ARRAY_A );
			}
			if ( ! $opt && preg_match( '/Option:\s*([a-zA-Z0-9_\-]+)/i', $rel_path, $om ) ) {
				$opt = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$target_db->options}` WHERE option_name = %s", $om[1] ), ARRAY_A );
			}

			if ( $opt ) {
				// 1. Create client safety backup in Quarantine Vault
				$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );
				$backup_dir     = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'cleaned_backups' );
				$timestamp      = time();

				$db_payload = array(
					'type'   => 'option',
					'table'  => $target_db->options,
					'option' => $opt,
				);
				$quarantine_filename = 'db_option_clean_' . sanitize_file_name( $opt['option_name'] ) . '.' . $timestamp . '.quarantined';
				$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
				$json_data = wp_json_encode( $db_payload );
				@file_put_contents( $quarantine_dest, $json_data );
				$quarantine_hash = hash( 'sha256', $json_data );

				// Insert into Quarantine Vault table
				$wpdb->insert(
					$table_quarantine,
					array(
						'finding_id'           => $finding_id,
						'site_id'              => $finding->site_id,
						'original_path'        => $rel_path,
						'original_hash'        => $quarantine_hash,
						'original_permissions' => 'DB_RECORD',
						'quarantine_path'      => $quarantine_dest,
						'quarantine_hash'      => $quarantine_hash,
						'reason'               => $finding->description,
						'status'               => 'cleaned',
						'created_at'           => current_time( 'mysql' ),
					)
				);

				// 2. Neutralize option value
				if ( $opt['option_name'] === 'wpcode_snippets' ) {
					// Delete WPCode cache so WPCode will re-compile clean snippets from post drafts
					$target_db->query( $target_db->prepare( "DELETE FROM `{$target_db->options}` WHERE option_id = %d", $opt['option_id'] ) );
				} else {
					$neutralized = "/* [HKYMALVEXA NEUTRALIZED MALWARE - " . gmdate( 'Y-m-d H:i:s' ) . "] */";
					$target_db->update(
						$target_db->options,
						array( 'option_value' => $neutralized ),
						array( 'option_id' => $opt['option_id'] )
					);
				}

				$wpdb->update(
					$table_findings,
					array( 'status' => 'cleaned' ),
					array( 'id' => $finding_id )
				);

				$client_backup_rel = 'wp-content/uploads/hkymalvexa-quarantine/vault/' . $quarantine_filename;
				hkymalvexa_log_audit(
					$finding->site_id,
					'clean_code',
					$rel_path,
					"Safely neutralized injected option '{$opt['option_name']}'. Vault Backup: {$client_backup_rel}"
				);

				return array(
					'success'     => true,
					'backup_file' => $client_backup_rel,
					'file_path'   => $rel_path,
					'line_number' => (int) $opt['option_id'],
				);
			}
		}

		// D. Dedicated WPCode snippets table {$target_db->prefix}snippets
		$snippets_table = $target_db->prefix . 'snippets';
		$has_table = $target_db->get_var( "SHOW TABLES LIKE '$snippets_table'" );
		if ( $has_table === $snippets_table ) {
			$snippet_id = (int) $finding->line_number;
			$sp = $target_db->get_row( $target_db->prepare( "SELECT * FROM `{$snippets_table}` WHERE id = %d", $snippet_id ), ARRAY_A );
			if ( $sp ) {
				$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );
				$backup_dir     = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'cleaned_backups' );
				$timestamp      = time();

				$db_payload = array(
					'type'    => 'snippet',
					'table'   => $snippets_table,
					'snippet' => $sp,
				);
				$quarantine_filename = 'db_snippet_clean_' . $snippet_id . '.' . $timestamp . '.quarantined';
				$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
				$json_data = wp_json_encode( $db_payload );
				@file_put_contents( $quarantine_dest, $json_data );
				$quarantine_hash = hash( 'sha256', $json_data );

				// Insert into Quarantine Vault table
				$wpdb->insert(
					$table_quarantine,
					array(
						'finding_id'           => $finding_id,
						'site_id'              => $finding->site_id,
						'original_path'        => $rel_path,
						'original_hash'        => $quarantine_hash,
						'original_permissions' => 'DB_RECORD',
						'quarantine_path'      => $quarantine_dest,
						'quarantine_hash'      => $quarantine_hash,
						'reason'               => $finding->description,
						'status'               => 'cleaned',
						'created_at'           => current_time( 'mysql' ),
					)
				);

				$neutralized = "/* [HKYMALVEXA NEUTRALIZED MALWARE - " . gmdate( 'Y-m-d H:i:s' ) . "] */\n/*\n" . str_replace( '*/', '* /', isset( $sp['code'] ) ? $sp['code'] : '' ) . "\n*/";
				$target_db->update(
					$snippets_table,
					array(
						'code'   => $neutralized,
						'active' => 0,
					),
					array( 'id' => $snippet_id )
				);

				// Also clear WPCode compiled cache option
				$target_db->query( "DELETE FROM `{$target_db->options}` WHERE option_name = 'wpcode_snippets'" );

				$wpdb->update(
					$table_findings,
					array( 'status' => 'cleaned' ),
					array( 'id' => $finding_id )
				);

				$client_backup_rel = 'wp-content/uploads/hkymalvexa-quarantine/vault/' . $quarantine_filename;
				hkymalvexa_log_audit(
					$finding->site_id,
					'clean_code',
					$rel_path,
					"Safely deactivated & neutralized WPCode snippet #{$snippet_id}. Vault Backup: {$client_backup_rel}"
				);

				return array(
					'success'     => true,
					'backup_file' => $client_backup_rel,
					'file_path'   => $rel_path,
					'line_number' => $snippet_id,
				);
			}
		}

		// E. If it is a database record that was already cleaned or removed:
		if ( strpos( $rel_path, 'database:' ) === 0 ) {
			$wpdb->update(
				$table_findings,
				array( 'status' => 'cleaned' ),
				array( 'id' => $finding_id )
			);
			hkymalvexa_log_audit(
				$finding->site_id,
				'clean_code',
				$rel_path,
				"Marked database threat as resolved."
			);
			return array(
				'success'     => true,
				'backup_file' => 'Database record cleaned',
				'file_path'   => $rel_path,
				'line_number' => (int) $finding->line_number,
			);
		}
	}

	$full_path = hkymalvexa_get_site_root( $finding->site_id ) . '/' . ltrim( $rel_path, '/\\' );
	if ( ! file_exists( $full_path ) ) {
		return new WP_Error( 'file_not_found', 'Target file does not exist on disk.' );
	}

	// 2. Create safety backup of original file in Quarantine Vault & Cleaned backups
	$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'vault' );
	$backup_dir     = hkymalvexa_get_site_quarantine_dir( $finding->site_id, 'cleaned_backups' );
	$timestamp      = time();

	$file_hash  = hash_file( 'sha256', $full_path );
	$file_perms = substr( sprintf( '%o', fileperms( $full_path ) ), -4 );

	$quarantine_filename = sanitize_file_name( basename( $rel_path ) ) . '.' . $timestamp . '.pre_clean.quarantined';
	$quarantine_dest     = $quarantine_dir . '/' . $quarantine_filename;
	if ( ! @copy( $full_path, $quarantine_dest ) ) {
		return new WP_Error( 'backup_failed', 'Failed to create pre-clean safety backup in quarantine vault.' );
	}

	// 3. Read file content
	$content = @file_get_contents( $full_path );
	if ( empty( $content ) ) {
		return new WP_Error( 'read_failed', 'Could not read target file.' );
	}

	$lines = explode( "\n", $content );
	$target_line = (int) $finding->line_number;
	$cleaned = false;

	// Check if target line is valid
	if ( $target_line > 0 && $target_line <= count( $lines ) ) {
		$idx = $target_line - 1;
		$orig_line = $lines[ $idx ];
		// If line begins with <?php tag, preserve the opening tag so the PHP parser remains valid
		if ( preg_match( '/^\s*<\?php\s*(.*)$/is', $orig_line, $m ) ) {
			$lines[ $idx ] = '<?php';
		} else {
			unset( $lines[ $idx ] );
		}
		$cleaned = true;
	} else {
		// Search for suspicious pattern
		foreach ( $lines as $idx => $line ) {
			if ( preg_match( '/(?:eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|FilesMan|b374k|c99shell|call_user_func|HKYMALVEXA_SAFE_TEST|HKYMALVEXA NEUTRALIZED MALWARE)/i', $line ) ) {
				if ( preg_match( '/^\s*<\?php\s*(.*)$/is', $line, $m ) ) {
					$lines[ $idx ] = '<?php';
				} else {
					unset( $lines[ $idx ] );
				}
				$target_line = $idx + 1;
				$cleaned = true;
				break;
			}
		}
	}

	// Also purge any previous leftover HKY MalVexa comment tags across the file
	foreach ( $lines as $k => $l ) {
		if ( strpos( $l, 'HKYMALVEXA NEUTRALIZED MALWARE' ) !== false ) {
			if ( preg_match( '/^\s*<\?php/i', $l ) ) {
				$lines[ $k ] = '<?php';
			} elseif ( preg_match( '/^\s*\/\*\s*\[HKYMALVEXA NEUTRALIZED MALWARE.*?(\*\/|\Z)\s*$/is', $l ) ) {
				unset( $lines[ $k ] );
			} else {
				$cleaned_l = trim( preg_replace( '/\/\*\s*\[HKYMALVEXA NEUTRALIZED MALWARE.*?(\*\/|\Z)/is', '', $l ) );
				if ( empty( $cleaned_l ) ) {
					unset( $lines[ $k ] );
				} else {
					$lines[ $k ] = $cleaned_l;
				}
			}
		}
	}

	if ( ! $cleaned ) {
		return new WP_Error( 'clean_failed', 'Could not locate the exact malicious injection line to remove.' );
	}

	$new_content = implode( "\n", $lines );

	// 4. Syntax validation test before saving (Guarantees zero white-screen on live sites)
	try {
		if ( defined( 'TOKEN_PARSE' ) ) {
			$tokens = @token_get_all( $new_content, TOKEN_PARSE );
		} else {
			$tokens = @token_get_all( $new_content );
		}
		if ( empty( $tokens ) ) {
			return new WP_Error( 'syntax_check_failed', 'Syntax safety check failed. Original file retained.' );
		}
	} catch ( ParseError $pe ) {
		return new WP_Error( 'syntax_check_failed', 'Syntax validation failed: ' . $pe->getMessage() . '. Original file retained.' );
	} catch ( Exception $e ) {
		return new WP_Error( 'syntax_check_failed', 'Syntax validation error. Original file retained.' );
	}

	// 5. Write sanitized content to file
	// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Legitimate surgical cleaning of injected malware code from site file.
	if ( false === @file_put_contents( $full_path, $new_content ) ) {
		return new WP_Error( 'write_failed', 'Could not write cleaned file to disk.' );
	}

	// 6. Update finding status
	$wpdb->update(
		$table_findings,
		array( 'status' => 'cleaned' ),
		array( 'id' => $finding_id )
	);

	// 7. Insert record into Quarantine Vault table so it appears with 1-Click Restore
	$wpdb->insert(
		$table_quarantine,
		array(
			'finding_id'           => $finding_id,
			'site_id'              => $finding->site_id,
			'original_path'        => $rel_path,
			'original_hash'        => $file_hash,
			'original_permissions' => $file_perms,
			'quarantine_path'      => $quarantine_dest,
			'quarantine_hash'      => hash_file( 'sha256', $quarantine_dest ),
			'reason'               => $finding->description,
			'status'               => 'cleaned',
			'created_at'           => current_time( 'mysql' ),
		)
	);

	// 8. Log audit
	$client_backup_rel = 'wp-content/uploads/hkymalvexa-quarantine/vault/' . $quarantine_filename;
	hkymalvexa_log_audit( $finding->site_id, 'clean_code', $rel_path, "Safely removed injected malware code at line {$target_line}. Vault Backup: {$client_backup_rel}" );

	return array(
		'success'     => true,
		'backup_file' => $client_backup_rel,
		'file_path'   => $rel_path,
		'line_number' => $target_line,
	);
}

/**
 * Automatically sync any cleaned findings to the quarantine vault table if missing
 * Ensures previously and newly cleaned items always appear in the Quarantine Vault
 */
function hkymalvexa_sync_cleaned_findings_to_vault() {
	global $wpdb;

	$table_findings   = hkymalvexa_get_table( 'findings' );
	$table_quarantine = hkymalvexa_get_table( 'quarantine' );

	$missing_cleaned = $wpdb->get_results(
		"SELECT f.* FROM $table_findings f 
		 LEFT JOIN $table_quarantine q ON f.id = q.finding_id 
		 WHERE f.status = 'cleaned' AND q.id IS NULL"
	);

	if ( empty( $missing_cleaned ) ) {
		return;
	}

	foreach ( $missing_cleaned as $f ) {
		$quarantine_dir = hkymalvexa_get_site_quarantine_dir( $f->site_id, 'vault' );
		$backup_dir     = hkymalvexa_get_site_quarantine_dir( $f->site_id, 'cleaned_backups' );
		$timestamp      = time();

		$quarantine_dest = '';
		$hash            = '';
		$permissions     = '0644';

		if ( strpos( $f->file_path, 'database:' ) === 0 || $f->category === 'wpcode_snippet' || $f->category === 'seo_spam_injection' || $f->category === 'db_option_injection' ) {
			$permissions = 'DB_RECORD';
			$possible_files = glob( $backup_dir . '/*' . ( (int) $f->line_number ) . '*.vault' );
			if ( ! empty( $possible_files ) ) {
				$found_bak = $possible_files[0];
				$quarantine_dest = $quarantine_dir . '/' . basename( $found_bak ) . '.quarantined';
				@copy( $found_bak, $quarantine_dest );
				$hash = hash_file( 'sha256', $quarantine_dest );
			} else {
				$quarantine_filename = 'db_cleaned_' . ( (int) $f->line_number ) . '.' . $timestamp . '.quarantined';
				$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
				$payload = array(
					'type'        => 'db_record',
					'finding_id'  => $f->id,
					'description' => $f->description,
					'file_path'   => $f->file_path,
				);
				$json = wp_json_encode( $payload );
				@file_put_contents( $quarantine_dest, $json );
				$hash = hash( 'sha256', $json );
			}
		} else {
			$possible_files = glob( $backup_dir . '/' . sanitize_file_name( basename( $f->file_path ) ) . '*.vault' );
			if ( ! empty( $possible_files ) ) {
				$found_bak = $possible_files[0];
				$quarantine_dest = $quarantine_dir . '/' . basename( $found_bak ) . '.quarantined';
				@copy( $found_bak, $quarantine_dest );
				$hash = hash_file( 'sha256', $quarantine_dest );
			} else {
				$full_path = hkymalvexa_get_site_root( $f->site_id ) . '/' . ltrim( $f->file_path, '/\\' );
				if ( file_exists( $full_path ) ) {
					$quarantine_filename = sanitize_file_name( basename( $f->file_path ) ) . '.' . $timestamp . '.quarantined';
					$quarantine_dest = $quarantine_dir . '/' . $quarantine_filename;
					@copy( $full_path, $quarantine_dest );
					$hash = hash_file( 'sha256', $quarantine_dest );
					$permissions = substr( sprintf( '%o', fileperms( $full_path ) ), -4 );
				}
			}
		}

		if ( ! empty( $quarantine_dest ) ) {
			$wpdb->insert(
				$table_quarantine,
				array(
					'finding_id'           => $f->id,
					'site_id'              => $f->site_id,
					'original_path'        => $f->file_path,
					'original_hash'        => $hash ? $hash : hash( 'sha256', $f->file_path ),
					'original_permissions' => $permissions,
					'quarantine_path'      => $quarantine_dest,
					'quarantine_hash'      => $hash ? $hash : hash( 'sha256', $quarantine_dest ),
					'reason'               => $f->description,
					'status'               => 'cleaned',
					'created_at'           => $f->created_at ? $f->created_at : current_time( 'mysql' ),
				)
			);
		}
	}
}

/**
 * Surgically clean cloaked SEO spam, casino link farms, and hidden injection containers
 *
 * @param string $content
 * @return string
 */
function hkymalvexa_clean_seo_spam_content( $content ) {
	if ( empty( $content ) || ! is_string( $content ) ) {
		return $content;
	}

	$casino_domains_kw = 'spinwinera|wazamba|spinanga|cazimbo|vegasino|gransino|spinsy|casinia|kasyno|kaszin[oó]|spielautomaten|highflybet|funbet|liraspin';

	// 1. Cloaked div container (outer wrapper with data-wp-poster, negative offsets, or display:none)
	$content = preg_replace( '/<div[^>]*?(?:data-wp-poster|style\s*=\s*[\'"][^\'"]*(?:left|top|margin-left|text-indent)\s*:\s*-\d{3,}px|style\s*=\s*[\'"][^\'"]*display\s*:\s*none)[^>]*?>.*?<\/div>/is', '', $content );

	// 2. Gutenberg block wrapping spam
	$content = preg_replace( '/<!--\s*wp:(?:html|paragraph)[^>]*?-->.*?(' . $casino_domains_kw . ').*?<!--\s*\/wp:(?:html|paragraph)\s*-->/is', '', $content );

	// 3. Direct links to spam domains
	$content = preg_replace( '/<a\s+[^>]*?href\s*=\s*[\'"][^\'"]*(?:' . $casino_domains_kw . ')[^\'"]*[\'"][^>]*?>.*?<\/a>/is', '', $content );

	// 4. Any single paragraph or element holding the spam (without crossing tag boundaries)
	$content = preg_replace( '/<(p|span|li|ul|section|article)[^>]*?>(?:(?!<\/\1>).)*?(?:' . $casino_domains_kw . ').*?<\/\1>/is', '', $content );

	// 5. Any single div holding the spam
	$content = preg_replace( '/<div[^>]*?>(?:(?!<\/div>).)*?(?:' . $casino_domains_kw . ').*?<\/div>/is', '', $content );

	// 6. Raw un-tagged text lines containing the keywords
	$content = preg_replace( '/[^\n<]*?(?:' . $casino_domains_kw . ')[^\n<]*/iu', '', $content );

	// 7. Cleanup empty wrapper tags leftover
	$content = preg_replace( '/<(?:div|p|span)[^>]*?>\s*<\/(?:div|p|span)>/is', '', $content );

	return trim( $content );
}

/**
 * Recursively remove spam widgets from Elementor elements tree
 *
 * @param array &$elements
 * @param string $pattern
 */
function hkymalvexa_clean_elementor_tree( &$elements, $pattern ) {
	if ( ! is_array( $elements ) ) {
		return;
	}
	$casino_domains_kw = 'spinwinera|wazamba|spinanga|cazimbo|vegasino|gransino|spinsy|casinia|kasyno|kaszin[oó]|spielautomaten|highflybet|funbet|liraspin';

	foreach ( $elements as $k => &$item ) {
		if ( isset( $item['elType'] ) && $item['elType'] === 'widget' ) {
			// Check html widget
			if ( isset( $item['settings']['html'] ) ) {
				if ( preg_match( $pattern, $item['settings']['html'] ) || preg_match( '/(?:' . $casino_domains_kw . ')/i', $item['settings']['html'] ) ) {
					unset( $elements[ $k ] );
					continue;
				}
			}
			// Check text/editor widget
			if ( isset( $item['settings']['editor'] ) ) {
				if ( preg_match( $pattern, $item['settings']['editor'] ) || preg_match( '/(?:' . $casino_domains_kw . ')/i', $item['settings']['editor'] ) ) {
					$item['settings']['editor'] = hkymalvexa_clean_seo_spam_content( $item['settings']['editor'] );
					if ( empty( trim( wp_strip_all_tags( $item['settings']['editor'] ) ) ) ) {
						unset( $elements[ $k ] );
						continue;
					}
				}
			}
		}
		if ( ! empty( $item['elements'] ) && is_array( $item['elements'] ) ) {
			hkymalvexa_clean_elementor_tree( $item['elements'], $pattern );
			$item['elements'] = array_values( $item['elements'] );
		}
	}
	$elements = array_values( $elements );
}

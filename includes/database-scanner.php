<?php
/**
 * HKY MalVexa Procedural Database Forensics Scanner
 * Inspects WPCode snippets, wp_options, wp_users, and wp_posts for injected payloads & rogue admins
 * Connects directly to the WordPress database ($wpdb) to inspect records
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get target site database (global $wpdb)
 *
 * @param int $site_id
 * @return wpdb Global WordPress database object
 */
function hkymalvexa_get_target_db( $site_id = 0 ) {
	global $wpdb;
	return $wpdb;
}

/**
 * Perform comprehensive database forensic analysis on the target site
 *
 * @param int $site_id
 * @return array List of findings
 */
function hkymalvexa_scan_database( $site_id = 0 ) {
	$db = hkymalvexa_get_target_db( $site_id );
	$findings = array();
	$rules = hkymalvexa_get_malware_rules();

	// 1. Dedicated WPCode & Code Snippets Plugin Database Forensics
	// Modern WPCode (2.0+) and Code Snippets store active code in {$prefix}snippets
	$snippets_table = $db->prefix . 'snippets';
	$has_snippets_table = $db->get_var( "SHOW TABLES LIKE '$snippets_table'" );

	if ( $has_snippets_table === $snippets_table ) {
		$snippets = $db->get_results( "SELECT * FROM `{$snippets_table}`" );
		if ( ! empty( $snippets ) ) {
			foreach ( $snippets as $sp ) {
				$is_trashed = ( isset( $sp->status ) && $sp->status === 'trash' );
				$code = isset( $sp->code ) ? $sp->code : '';
				$is_neutralized = ( stripos( $code, 'HKYMALVEXA NEUTRALIZED MALWARE' ) !== false );

				// Skip if completely empty, or if already neutralized AND active on live site
				if ( empty( $code ) || ( $is_neutralized && ! $is_trashed ) ) {
					continue;
				}

				$snip_id = isset( $sp->id ) ? (int) $sp->id : 0;
				$title = ! empty( $sp->title ) ? $sp->title : ( ! empty( $sp->name ) ? $sp->name : 'Snippet #' . $snip_id );
				$code_type = isset( $sp->code_type ) ? $sp->code_type : 'php';
				$is_active = isset( $sp->active ) ? (int) $sp->active : 1;

				$found_threat = false;
				$trash_tag = $is_trashed ? ' [TRASHED]' : '';
				$trash_desc = $is_trashed ? '[TRASHED] ' : '';

				// Scan against verified malware rules
				foreach ( $rules as $rule ) {
					if ( preg_match( $rule['pattern'], $code ) ) {
						$findings[] = array(
							'severity'           => $rule['severity'],
							'classification'     => $rule['classification'],
							'confidence'         => $rule['confidence'],
							'category'           => 'wpcode_snippet',
							'file_path'          => "database:{$snippets_table} (WPCode Snippet #{$snip_id}: {$title}){$trash_tag}",
							'line_number'        => $snip_id,
							'evidence'           => esc_html( substr( $code, 0, 300 ) . ( strlen( $code ) > 300 ? '...' : '' ) ),
							'description'        => "{$trash_desc}Malicious code detected in WPCode snippet '{$title}' [Type: {$code_type}, Active: " . ( $is_active ? 'Yes' : 'No' ) . "]: " . $rule['description'],
							'recommended_action' => 'clean',
						);
						$found_threat = true;
						break;
					}
				}

				// Secondary high-risk check for backdoors, webshell indicators, and stealth execution
				if ( ! $found_threat ) {
					if ( stripos( $code, 'FilesMan' ) !== false ||
						 preg_match( '/eval\s*\(\s*(?:base64_decode|gzinflate)/i', $code ) ||
						 preg_match( '/\b(?:passthru|shell_exec|system|popen|proc_open)\s*\(/i', $code ) ) {
						$findings[] = array(
							'severity'           => 'critical',
							'classification'     => 'malicious',
							'confidence'         => 98,
							'category'           => 'wpcode_snippet',
							'file_path'          => "database:{$snippets_table} (WPCode Snippet #{$snip_id}: {$title}){$trash_tag}",
							'line_number'        => $snip_id,
							'evidence'           => esc_html( substr( $code, 0, 300 ) . ( strlen( $code ) > 300 ? '...' : '' ) ),
							'description'        => "{$trash_desc}Dangerous execution payload detected in WPCode snippet '{$title}' [Type: {$code_type}, Active: " . ( $is_active ? 'Yes' : 'No' ) . "]. Backdoor / Webshell execution signature detected.",
							'recommended_action' => 'clean',
						);
					}
				}
			}
		}
	}

	// 2. WPCode and Custom Snippets stored in {$prefix}posts
	$posts_table = $db->prefix . 'posts';
	$snippet_posts = $db->get_results(
		"SELECT ID, post_title, post_type, post_content, post_status 
		FROM `{$posts_table}` 
		WHERE (post_type IN ('wpcode', 'snippet', 'code_snippet') 
		   OR post_content LIKE '%FilesMan%' 
		   OR post_content LIKE '%eval(base64_decode%' 
		   OR post_content LIKE '%eval(gzinflate%')
		LIMIT 50"
	);

	if ( ! empty( $snippet_posts ) ) {
		foreach ( $snippet_posts as $sp ) {
			$is_trashed = ( isset( $sp->post_status ) && $sp->post_status === 'trash' );
			$code = $sp->post_content;
			$is_neutralized = ( stripos( $code, 'HKYMALVEXA NEUTRALIZED MALWARE' ) !== false );

			// Skip if completely empty, or if already neutralized AND active on live site
			if ( empty( $code ) || ( $is_neutralized && ! $is_trashed ) ) {
				continue;
			}

			$trash_tag = $is_trashed ? ' [TRASHED]' : '';
			$trash_desc = $is_trashed ? '[TRASHED] ' : '';

			$matched = false;
			foreach ( $rules as $rule ) {
				if ( preg_match( $rule['pattern'], $code ) ) {
					$findings[] = array(
						'severity'           => $rule['severity'],
						'classification'     => $rule['classification'],
						'confidence'         => $rule['confidence'],
						'category'           => 'wpcode_snippet',
						'file_path'          => "database:{$posts_table} (WPCode Snippet #{$sp->ID}: {$sp->post_title}){$trash_tag}",
						'line_number'        => (int) $sp->ID,
						'evidence'           => esc_html( substr( $code, 0, 300 ) . ( strlen( $code ) > 300 ? '...' : '' ) ),
						'description'        => "{$trash_desc}Malicious/suspicious code detected inside WPCode database snippet '{$sp->post_title}': " . $rule['description'],
						'recommended_action' => 'clean',
					);
					$matched = true;
					break;
				}
			}

			// Fallback check if signature didn't catch it but contains FilesMan / eval
			if ( ! $matched && ( stripos( $code, 'FilesMan' ) !== false || preg_match( '/eval\s*\(\s*(?:base64_decode|gzinflate)/i', $code ) ) ) {
				$findings[] = array(
					'severity'           => 'critical',
					'classification'     => 'malicious',
					'confidence'         => 98,
					'category'           => 'wpcode_snippet',
					'file_path'          => "database:{$posts_table} (WPCode Snippet #{$sp->ID}: {$sp->post_title}){$trash_tag}",
					'line_number'        => (int) $sp->ID,
					'evidence'           => esc_html( substr( $code, 0, 300 ) . ( strlen( $code ) > 300 ? '...' : '' ) ),
					'description'        => "{$trash_desc}Backdoor / Webshell execution signature detected in WPCode database snippet '{$sp->post_title}'.",
					'recommended_action' => 'clean',
				);
			}
		}
	}

	// 3. Rogue Administrator Users Inspection
	$users_table = $db->prefix . 'users';
	$usermeta_table = $db->prefix . 'usermeta';
	$cap_key = $db->prefix . 'capabilities';

	$admin_users = $db->get_results(
		$db->prepare(
			"SELECT u.ID, u.user_login, u.user_email, u.user_registered
			FROM `{$users_table}` u
			INNER JOIN `{$usermeta_table}` m ON u.ID = m.user_id
			WHERE m.meta_key = %s AND m.meta_value LIKE %s",
			$cap_key,
			'%administrator%'
		)
	);

	if ( ! empty( $admin_users ) ) {
		foreach ( $admin_users as $admin ) {
			if ( preg_match( '/^(?:wp_admin|system_admin|support_user|test_admin|backup_admin|admin_\d+|wordpress_\d+)$/i', $admin->user_login ) ) {
				$findings[] = array(
					'severity'           => 'high',
					'classification'     => 'suspicious',
					'confidence'         => 85,
					'category'           => 'rogue_admin',
					'file_path'          => "database:{$users_table} (User ID: {$admin->ID})",
					'line_number'        => (int) $admin->ID,
					'evidence'           => "Login: {$admin->user_login}, Email: {$admin->user_email}, Registered: {$admin->user_registered}",
					'description'        => "Suspicious administrator user ({$admin->user_login}) detected. Exploit scripts frequently create stealth accounts with this name pattern.",
					'recommended_action' => 'review',
				);
			}
		}
	}

	// 4. wp_options Injected Payloads & WPCode Header/Footer Injections
	$options_table = $db->prefix . 'options';
	$options_query = $db->get_results(
		"SELECT option_id, option_name, option_value
		FROM `{$options_table}`
		WHERE option_name NOT LIKE '\\_transient\\_%' 
		  AND option_name NOT LIKE '\\_site\\_transient\\_%'
		  AND (
		      option_name LIKE 'wpcode_%'
		   OR option_name LIKE 'ihaf_%'
		   OR option_value LIKE '%FilesMan%'
		   OR option_value LIKE '%<script%'
		   OR option_value LIKE '%<iframe%'
		   OR option_value LIKE '%eval(%'
		   OR option_value LIKE '%base64_decode(%'
		  )
		LIMIT 60"
	);

	if ( ! empty( $options_query ) ) {
		foreach ( $options_query as $opt ) {
			$val = $opt->option_value;
			if ( empty( $val ) || stripos( $val, 'HKYMALVEXA NEUTRALIZED MALWARE' ) !== false ) {
				continue;
			}
			if ( preg_match( '/(?:slot88|joker123|sbobet|viagra|cialis|online-casino|FilesMan|eval\s*\(\s*(?:gzinflate|base64_decode)|(?:window|document)\.location(?:\.href)?\s*=\s*[\'"]http)/i', $val ) ) {
				$findings[] = array(
					'severity'           => 'critical',
					'classification'     => 'malicious',
					'confidence'         => 92,
					'category'           => 'db_option_injection',
					'file_path'          => "database:{$options_table} (Option: {$opt->option_name})",
					'line_number'        => (int) $opt->option_id,
					'evidence'           => esc_html( substr( $val, 0, 200 ) . '...' ),
					'description'        => "Malicious script/spam/backdoor content injected inside option '{$opt->option_name}'.",
					'recommended_action' => 'review',
				);
			}
		}
	}

	// 5. wp_posts External Script/Iframe Injections
	// phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Scanning database content for malicious script tags.
	$script_tag = '<' . 'script';
	$posts_query = $db->get_results(
		$db->prepare(
			"SELECT ID, post_title, post_content, post_status 
			FROM `{$posts_table}`
			WHERE (post_content LIKE %s
			   OR post_content LIKE %s)
			LIMIT 30",
			'%' . $db->esc_like( $script_tag ) . '%src=%',
			'%<iframe%'
		)
	);

	if ( ! empty( $posts_query ) ) {
		foreach ( $posts_query as $post ) {
			$is_trashed = ( isset( $post->post_status ) && $post->post_status === 'trash' );
			$content = $post->post_content;
			$is_neutralized = ( stripos( $content, 'HKYMALVEXA NEUTRALIZED MALWARE' ) !== false );
			if ( empty( $content ) || ( $is_neutralized && ! $is_trashed ) ) {
				continue;
			}
			$trash_tag = $is_trashed ? ' [TRASHED]' : '';
			$trash_desc = $is_trashed ? '[TRASHED] ' : '';

			// phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Scanning database content for rogue script injection.
			if ( preg_match( '/' . '<' . 'script\s+src=[\'"]https?:\/\/(?:[a-zA-Z0-9\-_]+\.)*(?:ru|pw|top|xyz|cc|su)\/[^\'"]*[\'"]/i', $post->post_content, $m ) ) {
				$findings[] = array(
					'severity'           => 'high',
					'classification'     => 'malicious',
					'confidence'         => 90,
					'category'           => 'post_script_injection',
					'file_path'          => "database:{$posts_table} (Post ID: {$post->ID}){$trash_tag}",
					'line_number'        => (int) $post->ID,
					'evidence'           => esc_html( $m[0] ),
					'description'        => "{$trash_desc}Post '{$post->post_title}' contains external malicious script tag injection.",
					'recommended_action' => 'review',
				);
			}
		}
	}

	// 6. Blackhat SEO Cloaked Spam, Casino Link Farms & Elementor Injections
	$seo_spam_pattern = '/(?:data-wp-poster|position\s*:\s*absolute\s*;\s*(?:[^\'"]*?)left\s*:\s*-\d{3,}px|-48592px|text-indent\s*:\s*-\d{4,}px|style\s*=\s*\\\\?[\'"][^\\\\\'"]*display\s*:\s*none[^\\\\\'"]*\\\\?[\'"].*?(?:kasyno|casino|wazamba|spinwinera)|(?:kasyno|kaszin[oó]|casino|wazamba|spinanga|cazimbo|vegasino|gransino|spinsy|spielautomaten|highflybet|funbet|casinia|liraspin).*?(?:kasyno|kaszin[oó]|casino|wazamba|spinanga|cazimbo|vegasino|gransino|spinsy|spielautomaten|highflybet|funbet|casinia|liraspin))/is';

	// A. Check wp_posts for SEO / Casino Spam
	$spam_posts = $db->get_results(
		"SELECT ID, post_title, post_type, post_content, post_status, post_parent 
		FROM `{$posts_table}` 
		WHERE (post_content LIKE '%data-wp-poster%'
		   OR post_content LIKE '%-48592px%'
		   OR post_content LIKE '%left: -%px%'
		   OR post_content LIKE '%left:-%px%'
		   OR post_content LIKE '%margin-left: -%px%'
		   OR post_content LIKE '%margin-left:-%px%'
		   OR post_content LIKE '%text-indent: -%px%'
		   OR post_content LIKE '%text-indent:-%px%'
		   OR post_content LIKE '%Spinwinera%'
		   OR post_content LIKE '%Wazamba%'
		   OR post_content LIKE '%Spinanga%'
		   OR post_content LIKE '%Cazimbo%'
		   OR post_content LIKE '%Vegasino%'
		   OR post_content LIKE '%Gransino%'
		   OR post_content LIKE '%Spinsy%'
		   OR post_content LIKE '%Casinia%'
		   OR (post_content LIKE '%style=%display:none%' AND (post_content LIKE '%kasyno%' OR post_content LIKE '%casino%' OR post_content LIKE '%slot%'))
		)
		LIMIT 50"
	);

	$reported_spam_post_ids = array();

	if ( ! empty( $spam_posts ) ) {
		foreach ( $spam_posts as $sp ) {
			$content = $sp->post_content;
			if ( empty( $content ) ) {
				continue;
			}
			if ( preg_match( $seo_spam_pattern, $content, $sm ) ) {
				$actual_id = (int) $sp->ID;
				$title = ! empty( $sp->post_title ) ? $sp->post_title : 'Post #' . $actual_id;

				if ( $sp->post_type === 'revision' && ! empty( $sp->post_parent ) ) {
					$parent = $db->get_row( $db->prepare( "SELECT ID, post_title FROM `{$posts_table}` WHERE ID = %d", $sp->post_parent ) );
					if ( $parent ) {
						$actual_id = (int) $parent->ID;
						$title = ! empty( $parent->post_title ) ? $parent->post_title : 'Page #' . $actual_id;
					}
				}

				// Skip duplicate finding if this page or revision has already been reported
				if ( in_array( $actual_id, $reported_spam_post_ids, true ) || in_array( (int) $sp->ID, $reported_spam_post_ids, true ) ) {
					continue;
				}

				$is_trashed = ( isset( $sp->post_status ) && $sp->post_status === 'trash' );
				$trash_tag = $is_trashed ? ' [TRASHED]' : '';
				$trash_desc = $is_trashed ? '[TRASHED] ' : '';

				$findings[] = array(
					'severity'           => 'high',
					'classification'     => 'malicious',
					'confidence'         => 98,
					'category'           => 'seo_spam_injection',
					'file_path'          => "database:{$posts_table} (Page ID: {$actual_id} - {$title}){$trash_tag}",
					'line_number'        => $actual_id,
					'evidence'           => esc_html( substr( $sm[0], 0, 300 ) . ( strlen( $sm[0] ) > 300 ? '...' : '' ) ),
					'description'        => "{$trash_desc}Blackhat SEO / Casino spam injection detected in '{$title}'. Cloaked off-screen content with hidden external links.",
					'recommended_action' => 'clean',
				);
				$reported_spam_post_ids[] = $actual_id;
				$reported_spam_post_ids[] = (int) $sp->ID;
			}
		}
	}

	// B. Check wp_postmeta (Elementor widget data, revisions, drafts & page builder JSON)
	$postmeta_table = $db->prefix . 'postmeta';
	$spam_meta = $db->get_results(
		"SELECT m.meta_id, m.post_id, m.meta_key, m.meta_value, p.post_title, p.post_status, p.post_parent, p.post_type
		FROM `{$postmeta_table}` m
		LEFT JOIN `{$posts_table}` p ON p.ID = m.post_id
		WHERE (m.meta_value LIKE '%data-wp-poster%'
		   OR m.meta_value LIKE '%-48592px%'
		   OR m.meta_value LIKE '%left: -%px%'
		   OR m.meta_value LIKE '%left:-%px%'
		   OR m.meta_value LIKE '%left%-%px%'
		   OR m.meta_value LIKE '%Spinwinera%'
		   OR m.meta_value LIKE '%Wazamba%'
		   OR m.meta_value LIKE '%Spinanga%'
		   OR m.meta_value LIKE '%Cazimbo%'
		   OR m.meta_value LIKE '%Vegasino%'
		   OR m.meta_value LIKE '%Gransino%'
		   OR m.meta_value LIKE '%Spinsy%'
		   OR m.meta_value LIKE '%Casinia%'
		   OR m.meta_value LIKE '%kasyno%'
		   OR m.meta_value LIKE '%kaszinó%'
		  )
		LIMIT 50"
	);

	if ( ! empty( $spam_meta ) ) {
		foreach ( $spam_meta as $meta ) {
			$val = $meta->meta_value;
			if ( empty( $val ) ) {
				continue;
			}

			$actual_id = (int) $meta->post_id;
			$title = ! empty( $meta->post_title ) ? $meta->post_title : 'Page #' . $actual_id;

			// If this postmeta belongs to a revision, resolve the actual parent page
			if ( isset( $meta->post_type ) && $meta->post_type === 'revision' && ! empty( $meta->post_parent ) ) {
				$parent = $db->get_row( $db->prepare( "SELECT ID, post_title FROM `{$posts_table}` WHERE ID = %d", $meta->post_parent ) );
				if ( $parent ) {
					$actual_id = (int) $parent->ID;
					$title = ! empty( $parent->post_title ) ? $parent->post_title : 'Page #' . $actual_id;
				}
			}

			// If already reported, avoid duplicate alerts
			if ( in_array( $actual_id, $reported_spam_post_ids, true ) || in_array( (int) $meta->post_id, $reported_spam_post_ids, true ) ) {
				continue;
			}

			if ( preg_match( $seo_spam_pattern, $val, $sm ) ) {
				$is_trashed = ( isset( $meta->post_status ) && $meta->post_status === 'trash' );
				$trash_tag = $is_trashed ? ' [TRASHED]' : '';
				$trash_desc = $is_trashed ? '[TRASHED] ' : '';

				$findings[] = array(
					'severity'           => 'high',
					'classification'     => 'malicious',
					'confidence'         => 98,
					'category'           => 'seo_spam_injection',
					'file_path'          => "database:{$posts_table} (Page ID: {$actual_id} - {$title} [Elementor Widget]){$trash_tag}",
					'line_number'        => $actual_id,
					'evidence'           => esc_html( substr( $sm[0], 0, 300 ) . ( strlen( $sm[0] ) > 300 ? '...' : '' ) ),
					'description'        => "{$trash_desc}Blackhat SEO / Casino spam widget detected inside Elementor page builder data for '{$title}'.",
					'recommended_action' => 'clean',
				);
				$reported_spam_post_ids[] = $actual_id;
				$reported_spam_post_ids[] = (int) $meta->post_id;
			}
		}
	}

	// C. Check wp_options (Widgets, Custom HTML, Theme Options)
	$spam_options = $db->get_results(
		"SELECT option_id, option_name, option_value
		FROM `{$options_table}`
		WHERE option_name NOT LIKE '\\_transient\\_%'
		  AND (option_value LIKE '%data-wp-poster%'
		   OR option_value LIKE '%left: -%px%'
		   OR option_value LIKE '%left:-%px%'
		  )
		LIMIT 30"
	);

	if ( ! empty( $spam_options ) ) {
		foreach ( $spam_options as $opt ) {
			$val = $opt->option_value;
			if ( empty( $val ) ) {
				continue;
			}
			if ( preg_match( $seo_spam_pattern, $val, $sm ) ) {
				$findings[] = array(
					'severity'           => 'high',
					'classification'     => 'malicious',
					'confidence'         => 98,
					'category'           => 'seo_spam_injection',
					'file_path'          => "database:{$options_table} (Option: {$opt->option_name})",
					'line_number'        => (int) $opt->option_id,
					'evidence'           => esc_html( substr( $sm[0], 0, 300 ) . ( strlen( $sm[0] ) > 300 ? '...' : '' ) ),
					'description'        => "Blackhat SEO spam container injected inside option '{$opt->option_name}'.",
					'recommended_action' => 'clean',
				);
			}
		}
	}

	return $findings;
}

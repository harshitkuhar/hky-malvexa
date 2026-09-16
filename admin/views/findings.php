<?php
/**
 * HKY MalVexa Findings & Evidence View
 */
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals
// phpcs:disable WordPress.DB.DirectDatabaseQuery
// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;
$table_findings   = hkymalvexa_get_table( 'findings' );
$table_quarantine = hkymalvexa_get_table( 'quarantine' );
$current_site_id  = hkymalvexa_get_current_site_id();

// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only UI tab filter parameter.
$status_filter = isset( $_GET['status'] ) ? sanitize_text_field( wp_unslash( $_GET['status'] ) ) : 'new';

// Auto-reopen any restored findings so they immediately appear in Active / Unresolved
$wpdb->query( "UPDATE `{$table_findings}` SET status = 'new' WHERE status = 'restored'" );

$hkymalvexa_esc  = method_exists( $wpdb, 'esc_like' ) ? $wpdb->esc_like( 'hky-malvexa' ) : addcslashes( 'hky-malvexa', '_%\\' );
$hkymalvexa_like = '%' . $hkymalvexa_esc . '%';

// Fetch findings for this WordPress site
if ( $status_filter === 'quarantined' ) {
	$findings = $wpdb->get_results(
		$wpdb->prepare(
			"SELECT f.*, 
			        (SELECT COUNT(*) FROM `{$table_quarantine}` q WHERE q.finding_id = f.id AND q.status = 'restored') as was_restored
			FROM `{$table_findings}` f 
			WHERE f.file_path NOT LIKE %s AND f.status IN ('quarantined', 'cleaned') 
			ORDER BY f.id DESC LIMIT 100",
			$hkymalvexa_like
		)
	);
} else {
	$status_filter = 'new';
	$findings = $wpdb->get_results(
		$wpdb->prepare(
			"SELECT f.*, 
			        (SELECT COUNT(*) FROM `{$table_quarantine}` q WHERE q.finding_id = f.id AND q.status = 'restored') as was_restored
			FROM `{$table_findings}` f 
			WHERE f.file_path NOT LIKE %s AND f.status = %s 
			ORDER BY f.id DESC LIMIT 100",
			$hkymalvexa_like,
			'new'
		)
	);
}

$count_new = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$table_findings}` WHERE status = 'new' AND file_path NOT LIKE %s", $hkymalvexa_like ) );
$count_quarantined = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$table_findings}` WHERE status IN ('quarantined', 'cleaned') AND file_path NOT LIKE %s", $hkymalvexa_like ) );
?>

<div class="wrap hkymalvexa-wrap">

	<div class="hkymalvexa-header">
		<div class="hkymalvexa-title-area">
			<h1><span class="dashicons dashicons-shield"></span> Scan Center & Threat Findings</h1>
			<p>Execute live emergency scans, inspect threat evidence, and take safe remediation actions.</p>
		</div>
		<div class="hkymalvexa-header-actions" style="display: flex; align-items: center; gap: 10px;">
			<span class="wpd-badge" style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: 600;">
				<span class="dashicons dashicons-shield" style="font-size: 14px; vertical-align: middle; margin-right: 2px;"></span> Threat Protection Active
			</span>
		</div>
	</div>

	<!-- Integrated Scan Launcher Card -->
	<div class="wpd-card" style="margin-bottom: 20px;">
		<div class="wpd-card-header" style="display: flex; justify-content: space-between; align-items: center;">
			<h2 class="wpd-card-title"><span class="dashicons dashicons-search"></span> Launch Emergency Scan Job</h2>
			<span style="font-size: 12px; color: var(--wpd-text-muted);">Zero-timeout batched scanner with real-time logging</span>
		</div>
		<div class="wpd-card-body">
			<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; align-items: end;">
				<div>
					<label class="wpd-label" style="font-weight: 600; font-size: 12px; margin-bottom: 6px; display: block; color: var(--wpd-text-main);">Target WordPress Installation</label>
					<div style="height: 40px; box-sizing: border-box; padding: 9px 12px; border-radius: 6px; border: 1px solid var(--wpd-card-border); background: #f8fafc; font-weight: 600; font-size: 13px; color: var(--wpd-text-main); display: flex; align-items: center; justify-content: space-between;">
						<span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
							<span class="dashicons dashicons-admin-site" style="color: var(--wpd-primary); vertical-align: middle; margin-right: 4px;"></span>
							<?php echo esc_html( get_bloginfo( 'name' ) ? get_bloginfo( 'name' ) : 'This Site' ); ?>
							<code style="font-size: 11px; font-weight: normal; margin-left: 6px; color: var(--wpd-text-muted);"><?php echo esc_html( home_url() ); ?></code>
						</span>
						<span class="wpd-badge" style="background: #eff6ff; color: #1d4ed8; font-size: 10px; padding: 2px 6px;">Hosted</span>
					</div>
					<input type="hidden" id="wpd-current-site-id" value="<?php echo (int) $current_site_id; ?>">
				</div>

				<div>
					<label class="wpd-label" style="font-weight: 600; font-size: 12px; margin-bottom: 6px; display: block; color: var(--wpd-text-main);">Scan Profile</label>
					<div style="height: 40px; box-sizing: border-box; padding: 9px 12px; border-radius: 6px; border: 1px solid var(--wpd-card-border); background: #f8fafc; font-weight: 600; font-size: 13px; color: var(--wpd-text-main); display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-shield" style="color: var(--wpd-primary); font-size: 16px; width: 16px; height: 16px;"></span>
						<span>Full Deep Scan (Files, Core & Database)</span>
					</div>
					<input type="hidden" id="wpd-select-type" value="deep">
				</div>

				<div>
					<button id="wpd-btn-start-scan" class="wpd-btn wpd-btn-emergency" style="width: 100%; height: 40px; justify-content: center; padding: 9px 18px; font-size: 14px;">
						<span class="dashicons dashicons-controls-play"></span> Start Emergency Scan
					</button>
				</div>
			</div>

			<!-- Live Progress Box (Hidden initially) -->
			<div id="wpd-scan-progress-box" class="wpd-scan-box" style="display: none; margin-top: 20px;">
				<div style="display: flex; justify-content: space-between; align-items: center;">
					<h3 style="margin: 0; font-size: 14px; color: var(--wpd-text-main); font-weight: 600; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-update spin" style="color: var(--wpd-cyan);"></span>
						Scan In Progress (Zero-Timeout Batched Engine)
					</h3>
					<span id="wpd-progress-text" style="font-weight: 700; color: var(--wpd-cyan); font-size: 15px;">0%</span>
				</div>

				<div class="wpd-progress-container" style="margin-top: 10px;">
					<div class="wpd-progress-bar-wrap">
						<div id="wpd-progress-bar" class="wpd-progress-bar"></div>
					</div>
					<div class="wpd-scan-stats" style="margin-top: 6px; display: flex; justify-content: space-between; font-size: 12px;">
						<span id="wpd-scanned-count">Preparing file catalog...</span>
						<span id="wpd-findings-count" style="color: var(--wpd-rose); font-weight: 600;">0 findings detected</span>
					</div>
				</div>

				<!-- Live Terminal Logs -->
				<div id="wpd-scan-terminal" class="wpd-terminal" style="margin-top: 12px; max-height: 180px; overflow-y: auto;">
					<div>[<?php echo esc_html( current_time( 'H:i:s' ) ); ?>] Scan engine ready. Click Start Emergency Scan to begin.</div>
				</div>
			</div>
		</div>
	</div>

	<!-- Status Filter Tabs Bar -->
	<div class="wpd-card" style="margin-bottom: 20px;">
		<div class="wpd-card-body" style="padding: 14px 20px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 16px;">
			<div style="font-size: 13px; font-weight: 600; color: var(--wpd-text-main);">
				Threats on Current WordPress Site
			</div>

			<!-- Status Filter Pills -->
			<div style="display: flex; gap: 8px;">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=hkymalvexa-findings&status=new' ) ); ?>" class="wpd-btn <?php echo ( $status_filter === 'new' ) ? 'wpd-btn-primary' : 'wpd-btn-secondary'; ?> wpd-btn-sm">
					Active / Unresolved (<?php echo esc_html( $count_new ); ?>)
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=hkymalvexa-findings&status=quarantined' ) ); ?>" class="wpd-btn <?php echo ( $status_filter === 'quarantined' ) ? 'wpd-btn-primary' : 'wpd-btn-secondary'; ?> wpd-btn-sm">
					Quarantined & Cleaned (<?php echo esc_html( $count_quarantined ); ?>)
				</a>
			</div>
		</div>
	</div>

	<!-- Findings Table -->
	<div class="wpd-card">
		<div class="wpd-card-body" style="padding: 0;">
			<?php if ( empty( $findings ) ) : ?>
				<div style="padding: 50px 20px; text-align: center; color: var(--wpd-text-muted);">
					<span class="dashicons dashicons-yes-alt" style="font-size: 46px; width: 46px; height: 46px; color: var(--wpd-emerald); margin-bottom: 12px;"></span>
					<h3 style="color: var(--wpd-text-main); margin: 0 0 6px 0; font-size: 17px;">No Findings</h3>
					<p style="margin: 0; font-size: 13px;">No suspicious or malicious files detected on this site under the selected filter.</p>
				</div>
			<?php else : ?>
				<table class="wpd-table">
					<thead>
						<tr>
							<th style="width: 100px;">Severity</th>
							<th style="width: 90px;">Confidence</th>
							<th>File / Target Location</th>
							<th style="width: 70px;">Line</th>
							<th style="width: 140px;">Category</th>
							<th style="width: 190px; text-align: right;">Action</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $findings as $f ) : ?>
							<tr>
								<td>
									<span class="wpd-tag wpd-tag-<?php echo esc_attr( $f->severity ); ?>">
										<?php echo esc_html( strtoupper( $f->severity ) ); ?>
									</span>
								</td>
								<td><strong style="color: var(--wpd-text-main);"><?php echo (int) $f->confidence; ?>%</strong></td>
								<td>
									<div style="display: flex; align-items: center; gap: 6px;">
										<?php if ( stripos( $f->file_path, '[TRASHED]' ) !== false || stripos( $f->description, '[TRASHED]' ) !== false ) : ?>
											<span class="wpd-badge wpd-badge-trashed" style="background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; font-weight: 700; font-size: 10.5px; padding: 2px 7px; border-radius: 4px; display: inline-flex; align-items: center; gap: 3px; white-space: nowrap;" title="This item is currently in Trash">
												<span class="dashicons dashicons-trash" style="font-size: 13px; width: 13px; height: 13px; line-height: 13px;"></span> TRASHED
											</span>
										<?php endif; ?>
										<?php if ( ! empty( $f->was_restored ) ) : ?>
											<span class="wpd-badge" style="background: #fef3c7; color: #b45309; border: 1px solid #fde68a; font-weight: 700; font-size: 10.5px; padding: 2px 7px; border-radius: 4px; display: inline-flex; align-items: center; gap: 3px; white-space: nowrap;" title="This threat was restored from Quarantine Vault back to the live site">
												<span class="dashicons dashicons-undo" style="font-size: 13px; width: 13px; height: 13px; line-height: 13px;"></span> RESTORED
											</span>
										<?php endif; ?>
										<code style="font-size: 12px; font-weight: 600; color: #0f172a; word-break: break-all;"><?php echo esc_html( trim( str_replace( array( ' [TRASHED]', '[TRASHED]' ), '', $f->file_path ) ) ); ?></code>
									</div>
								</td>
								<td><?php echo (int) $f->line_number; ?></td>
								<td>
									<?php if ( $f->category === 'seo_spam_injection' ) : ?>
										<span class="wpd-badge" style="background: #fef3c7; color: #b45309; border: 1px solid #fde68a; font-weight: 700; font-size: 11px; padding: 2px 7px; border-radius: 4px; display: inline-flex; align-items: center; gap: 3px; white-space: nowrap;">
											<span class="dashicons dashicons-admin-links" style="font-size: 13px; width: 13px; height: 13px; line-height: 13px;"></span> SEO SPAM
										</span>
									<?php else : ?>
										<code><?php echo esc_html( $f->category ); ?></code>
									<?php endif; ?>
								</td>
								<td style="text-align: right;">
									<div style="display: inline-flex; flex-wrap: nowrap; gap: 6px; align-items: center; justify-content: flex-end;">
										<button class="wpd-btn wpd-btn-secondary wpd-btn-sm wpd-btn-view-code" data-id="<?php echo (int) $f->id; ?>" title="Inspect code and take action">
											<span class="dashicons dashicons-visibility" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle;"></span> Inspect
										</button>
										<?php if ( ! in_array( $f->status, array( 'new', 'restored' ), true ) ) : ?>
											<span class="wpd-tag wpd-tag-<?php echo esc_attr( $f->status ); ?>"><?php echo esc_html( strtoupper( $f->status ) ); ?></span>
										<?php endif; ?>
									</div>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
	</div>

</div>

<!-- Centered Code Evidence Modal -->
<div id="wpd-code-modal" class="wpd-modal-backdrop">
	<div class="wpd-modal">
		<div class="wpd-modal-header">
			<div>
				<h3 id="wpd-code-modal-title" class="wpd-modal-title">Code Inspector</h3>
				<div id="wpd-code-modal-desc" style="font-size: 12px; color: var(--wpd-text-muted); margin-top: 3px;"></div>
			</div>
			<button type="button" class="wpd-modal-close" aria-label="Close">&times;</button>
		</div>
		<div class="wpd-modal-body">
			<div id="wpd-code-modal-evidence-box" style="margin-bottom: 14px; padding: 10px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 12px; display: none;">
				<strong style="color: var(--wpd-text-main);">Evidence / Reason:</strong>
				<div id="wpd-code-modal-evidence-text" style="color: #0369a1; margin-top: 4px; font-family: monospace; white-space: pre-wrap; word-break: break-all;"></div>
			</div>
			<div id="wpd-code-modal-content" class="wpd-code-container">
				Loading...
			</div>
		</div>
		<div class="wpd-modal-footer" id="wpd-code-modal-footer" style="padding: 12px 20px; border-top: 1px solid #e2e8f0; background: #f8fafc; display: flex; justify-content: space-between; align-items: center; border-radius: 0 0 12px 12px;">
			<div id="wpd-code-modal-status-text" style="font-size: 12px; color: var(--wpd-text-muted);">
				Inspect detected lines and select remediation.
			</div>
			<div id="wpd-code-modal-actions" style="display: flex; gap: 8px;">
				<!-- Remediations populated by JS -->
			</div>
		</div>
	</div>
</div>

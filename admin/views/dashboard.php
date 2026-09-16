<?php
/**
 * HKY MalVexa Dashboard View
 */
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals
// phpcs:disable WordPress.DB.DirectDatabaseQuery
// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$stats = hkymalvexa_get_dashboard_stats();

global $wpdb;
$table_scans    = hkymalvexa_get_table( 'scans' );
$table_findings = hkymalvexa_get_table( 'findings' );

$recent_scans    = $wpdb->get_results( "SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 5" );
$recent_findings = $wpdb->get_results( "SELECT * FROM `{$table_findings}` WHERE status = 'new' AND file_path NOT LIKE '%hky-malvexa%' ORDER BY id DESC LIMIT 6" );
?>

<div class="wrap hkymalvexa-wrap">

	<!-- Header Banner -->
	<div class="hkymalvexa-header">
		<div class="hkymalvexa-title-area">
			<h1><span class="dashicons dashicons-shield-alt"></span> HKY MalVexa <span class="hkymalvexa-badge">V1.0</span></h1>
			<p>WordPress Emergency Diagnosis, Malware Investigation, Cleanup & Recovery Platform</p>
		</div>
		<div class="hkymalvexa-header-actions" style="display: flex; align-items: center; gap: 10px;">
			<?php if ( $stats['protection_status'] === 'protected' ) : ?>
				<span class="wpd-badge" style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: 600;">
					<span class="dashicons dashicons-shield" style="font-size: 14px; vertical-align: middle; margin-right: 2px;"></span> Protected
				</span>
			<?php else : ?>
				<span class="wpd-badge" style="background: #fff1f2; color: #be123c; border: 1px solid #fecdd3; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: 600;">
					<span class="dashicons dashicons-warning" style="font-size: 14px; vertical-align: middle; margin-right: 2px;"></span> Threats Detected
				</span>
			<?php endif; ?>

			<a href="<?php echo esc_url( admin_url( 'admin.php?page=hkymalvexa-findings' ) ); ?>" class="wpd-btn wpd-btn-emergency">
				<span class="dashicons dashicons-controls-play"></span> Emergency Scan
			</a>
			<button id="wpd-btn-verify-site" class="wpd-btn wpd-btn-primary">
				<span class="dashicons dashicons-heart"></span> Verify Core Integrity
			</button>
		</div>
	</div>

	<!-- Stats Grid -->
	<div class="hkymalvexa-stats-grid">
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon <?php echo ( $stats['protection_status'] === 'protected' ) ? 'wpd-icon-emerald' : 'wpd-icon-rose'; ?>">
				<span class="dashicons <?php echo ( $stats['protection_status'] === 'protected' ) ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
			</div>
			<div>
				<div class="wpd-stat-val" style="font-size: 20px;">
					<?php echo ( $stats['protection_status'] === 'protected' ) ? 'Protected' : 'Threats Found'; ?>
				</div>
				<div class="wpd-stat-label">Security Status</div>
			</div>
		</div>
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon wpd-icon-cyan"><span class="dashicons dashicons-media-document"></span></div>
			<div>
				<div class="wpd-stat-val">
					<?php echo ( $stats['last_scanned_files'] > 0 ) ? esc_html( number_format( $stats['last_scanned_files'] ) ) : 'Ready'; ?>
				</div>
				<div class="wpd-stat-label">Files Cataloged</div>
			</div>
		</div>
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon wpd-icon-rose"><span class="dashicons dashicons-dismiss"></span></div>
			<div>
				<div class="wpd-stat-val"><?php echo esc_html( $stats['active_findings'] ); ?></div>
				<div class="wpd-stat-label">Active Threats</div>
			</div>
		</div>
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon wpd-icon-amber"><span class="dashicons dashicons-lock"></span></div>
			<div>
				<div class="wpd-stat-val"><?php echo esc_html( $stats['quarantined_files'] ); ?></div>
				<div class="wpd-stat-label">Quarantined & Neutralized</div>
			</div>
		</div>
	</div>

	<!-- Recent Critical Findings -->
	<div class="wpd-card">
		<div class="wpd-card-header">
			<h2 class="wpd-card-title"><span class="dashicons dashicons-warning"></span> Active Threats Requiring Review</h2>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=hkymalvexa-findings' ) ); ?>" class="wpd-btn wpd-btn-secondary wpd-btn-sm">View All Findings</a>
		</div>
		<div class="wpd-card-body" style="padding: 0;">
			<?php if ( empty( $recent_findings ) ) : ?>
				<div style="padding: 40px 20px; text-align: center; color: var(--wpd-text-muted);">
					<span class="dashicons dashicons-shield" style="font-size: 42px; width: 42px; height: 42px; color: var(--wpd-emerald); margin-bottom: 12px;"></span>
					<p style="margin: 0; font-size: 16px; font-weight: 600; color: var(--wpd-text-main);">No active malware or critical threats detected.</p>
					<p style="margin: 6px 0 0 0; font-size: 13px;">Your WordPress installation is clean according to current rules.</p>
				</div>
			<?php else : ?>
				<table class="wpd-table">
					<thead>
						<tr>
							<th>Severity</th>
							<th>Category</th>
							<th>Location</th>
							<th>Line</th>
							<th>Description</th>
							<th style="text-align: right;">Action</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $recent_findings as $f ) : ?>
							<tr>
								<td>
									<span class="wpd-tag wpd-tag-<?php echo esc_attr( $f->severity ); ?>">
										<?php echo esc_html( strtoupper( $f->severity ) ); ?>
									</span>
								</td>
								<td><code><?php echo esc_html( $f->category ); ?></code></td>
								<td><strong><?php echo esc_html( $f->file_path ); ?></strong></td>
								<td><?php echo (int) $f->line_number; ?></td>
								<td><?php echo esc_html( wp_trim_words( $f->description, 10 ) ); ?></td>
								<td style="text-align: right;">
									<button class="wpd-btn wpd-btn-secondary wpd-btn-sm wpd-btn-view-code" data-id="<?php echo (int) $f->id; ?>">
										Inspect Evidence
									</button>
									<?php if ( $f->recommended_action === 'quarantine' ) : ?>
										<button class="wpd-btn wpd-btn-emergency wpd-btn-sm wpd-btn-quarantine" data-id="<?php echo (int) $f->id; ?>">
											Quarantine
										</button>
									<?php elseif ( $f->recommended_action === 'restore_core' ) : ?>
										<button class="wpd-btn wpd-btn-primary wpd-btn-sm wpd-btn-repair-core" data-path="<?php echo esc_attr( $f->file_path ); ?>">
											Repair Core
										</button>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
	</div>

	<!-- Recent Scans -->
	<div class="wpd-card">
		<div class="wpd-card-header">
			<h2 class="wpd-card-title"><span class="dashicons dashicons-backup"></span> Recent Scan History</h2>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=hkymalvexa-findings' ) ); ?>" class="wpd-btn wpd-btn-secondary wpd-btn-sm">Launch Scan</a>
		</div>
		<div class="wpd-card-body" style="padding: 0;">
			<?php if ( empty( $recent_scans ) ) : ?>
				<div style="padding: 30px; text-align: center; color: var(--wpd-text-muted);">
					No previous scans recorded yet. Click <strong>Emergency Scan</strong> above to inspect your site.
				</div>
			<?php else : ?>
				<table class="wpd-table">
					<thead>
						<tr>
							<th>Scan ID</th>
							<th>Type</th>
							<th>Status</th>
							<th>Files Scanned</th>
							<th>Findings</th>
							<th>Started At</th>
							<th>Completed At</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $recent_scans as $s ) : ?>
							<tr>
								<td>#<?php echo (int) $s->id; ?></td>
								<td><span class="wpd-badge"><?php echo esc_html( strtoupper( $s->scan_type ) ); ?></span></td>
								<td>
									<span class="wpd-tag wpd-tag-<?php echo ( $s->status === 'completed' ) ? 'healthy' : 'medium'; ?>">
										<?php echo esc_html( strtoupper( $s->status ) ); ?>
									</span>
								</td>
								<td><?php echo number_format( (int) $s->scanned_files ); ?> / <?php echo number_format( (int) $s->total_files ); ?></td>
								<td>
									<strong><?php echo (int) $s->findings_count; ?></strong>
								</td>
								<td><?php echo esc_html( $s->started_at ); ?></td>
								<td><?php echo esc_html( $s->completed_at ? $s->completed_at : 'In progress' ); ?></td>
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

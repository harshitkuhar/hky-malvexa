<?php
/**
 * SiteCure Dashboard View
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$stats = sitecure_get_dashboard_stats();
$sites = sitecure_get_sites();

global $wpdb;
$table_scans = sitecure_get_table( 'scans' );
$table_findings = sitecure_get_table( 'findings' );
$table_sites = sitecure_get_table( 'sites' );

$recent_scans = $wpdb->get_results( "SELECT sc.*, s.name as site_name FROM $table_scans sc LEFT JOIN $table_sites s ON sc.site_id = s.id ORDER BY sc.id DESC LIMIT 5" );
$recent_findings = $wpdb->get_results( "SELECT f.*, s.name as site_name FROM $table_findings f LEFT JOIN $table_sites s ON f.site_id = s.id WHERE f.status = 'new' AND f.file_path NOT LIKE '%sitecure%' ORDER BY f.id DESC LIMIT 6" );
?>

<div class="wrap sitecure-wrap">

	<!-- Header Banner -->
	<div class="sitecure-header">
		<div class="sitecure-title-area">
			<h1><span class="dashicons dashicons-shield-alt"></span> SiteCure <span class="sitecure-badge">V1.0</span></h1>
			<p>WordPress Emergency Diagnosis, Malware Investigation, Cleanup & Recovery Platform</p>
		</div>
		<div class="sitecure-header-actions" style="display: flex; align-items: center; gap: 10px;">
			<?php if ( function_exists( 'sitecure_is_dev_mode' ) && sitecure_is_dev_mode() ) : ?>
				<span class="wpd-badge" style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: 600;">
					<span class="dashicons dashicons-superhero" style="font-size: 14px; vertical-align: middle; margin-right: 2px;"></span> Developer Unlimited
				</span>
			<?php else : ?>
				<span class="wpd-badge" style="background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: 600;">
					<span class="dashicons dashicons-admin-site" style="font-size: 14px; vertical-align: middle; margin-right: 2px;"></span> Free Plan: <?php echo count( $sites ); ?>/1 Site
				</span>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sitecure-sites' ) ); ?>" style="background: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%); color: #fff; border: none; border-radius: 20px; font-weight: 600; font-size: 11px; padding: 5px 12px; text-decoration: none; box-shadow: 0 2px 6px rgba(79,70,229,0.3);">
					<span class="dashicons dashicons-star-filled" style="font-size: 13px; width: 13px; height: 13px; vertical-align: middle; margin-right: 2px;"></span> Upgrade to Pro
				</a>
			<?php endif; ?>

			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sitecure-findings' ) ); ?>" class="wpd-btn wpd-btn-emergency">
				<span class="dashicons dashicons-warning"></span> Emergency Scan
			</a>
			<button id="wpd-btn-verify-site" class="wpd-btn wpd-btn-primary">
				<span class="dashicons dashicons-heart"></span> Verify Site Health
			</button>
		</div>
	</div>

	<!-- Stats Grid -->
	<div class="sitecure-stats-grid">
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon wpd-icon-cyan"><span class="dashicons dashicons-networking"></span></div>
			<div>
				<div class="wpd-stat-val"><?php echo esc_html( $stats['total_sites'] ); ?></div>
				<div class="wpd-stat-label">Managed Sites</div>
			</div>
		</div>
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon wpd-icon-emerald"><span class="dashicons dashicons-yes-alt"></span></div>
			<div>
				<div class="wpd-stat-val"><?php echo esc_html( $stats['healthy_sites'] ); ?></div>
				<div class="wpd-stat-label">Healthy Sites</div>
			</div>
		</div>
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon wpd-icon-rose"><span class="dashicons dashicons-dismiss"></span></div>
			<div>
				<div class="wpd-stat-val"><?php echo esc_html( $stats['critical_findings'] ); ?></div>
				<div class="wpd-stat-label">Critical Findings</div>
			</div>
		</div>
		<div class="wpd-stat-card">
			<div class="wpd-stat-icon wpd-icon-amber"><span class="dashicons dashicons-lock"></span></div>
			<div>
				<div class="wpd-stat-val"><?php echo esc_html( $stats['quarantined_files'] ); ?></div>
				<div class="wpd-stat-label">Quarantined Files</div>
			</div>
		</div>
	</div>

	<!-- Recent Critical Findings -->
	<div class="wpd-card">
		<div class="wpd-card-header">
			<h2 class="wpd-card-title"><span class="dashicons dashicons-warning"></span> Active Findings Requiring Review</h2>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sitecure-findings' ) ); ?>" class="wpd-btn wpd-btn-secondary wpd-btn-sm">View All Findings</a>
		</div>
		<div class="wpd-card-body" style="padding: 0;">
			<?php if ( empty( $recent_findings ) ) : ?>
				<div style="padding: 30px; text-align: center; color: var(--wpd-text-muted);">
					<span class="dashicons dashicons-shield" style="font-size: 38px; width: 38px; height: 38px; color: var(--wpd-emerald); margin-bottom: 10px;"></span>
					<p style="margin: 0; font-size: 15px; color: #fff;">No active malware or critical threats detected.</p>
					<p style="margin: 4px 0 0 0; font-size: 13px;">Your WordPress installation is clean according to current rules.</p>
				</div>
			<?php else : ?>
				<table class="wpd-table">
					<thead>
						<tr>
							<th>Site</th>
							<th>Severity</th>
							<th>Category</th>
							<th>Location</th>
							<th>Line</th>
							<th>Description</th>
							<th>Action</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $recent_findings as $f ) : ?>
							<tr>
								<td>
									<span class="wpd-badge">
										<?php echo esc_html( $f->site_name ? $f->site_name : 'Site #' . $f->site_id ); ?>
									</span>
								</td>
								<td>
									<span class="wpd-tag wpd-tag-<?php echo esc_attr( $f->severity ); ?>">
										<?php echo esc_html( strtoupper( $f->severity ) ); ?>
									</span>
								</td>
								<td><code><?php echo esc_html( $f->category ); ?></code></td>
								<td><strong><?php echo esc_html( $f->file_path ); ?></strong></td>
								<td><?php echo (int) $f->line_number; ?></td>
								<td><?php echo esc_html( wp_trim_words( $f->description, 10 ) ); ?></td>
								<td>
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
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sitecure-findings' ) ); ?>" class="wpd-btn wpd-btn-secondary wpd-btn-sm">Launch Scan</a>
		</div>
		<div class="wpd-card-body" style="padding: 0;">
			<?php if ( empty( $recent_scans ) ) : ?>
				<div style="padding: 24px; text-align: center; color: var(--wpd-text-muted);">
					No previous scans recorded yet. Run your first scan from the Scan Center!
				</div>
			<?php else : ?>
				<table class="wpd-table">
					<thead>
						<tr>
							<th>Scan ID</th>
							<th>Site</th>
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
								<td>
									<span class="wpd-badge">
										<?php echo esc_html( $s->site_name ? $s->site_name : 'Site #' . $s->site_id ); ?>
									</span>
								</td>
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

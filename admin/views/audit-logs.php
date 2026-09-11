<?php
/**
 * SiteCure Audit Logs View
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;
$table_audit = sitecure_get_table( 'audit_logs' );
$table_sites = sitecure_get_table( 'sites' );

$logs = $wpdb->get_results( "
	SELECT a.*, s.name as site_name 
	FROM $table_audit a 
	LEFT JOIN $table_sites s ON a.site_id = s.id 
	ORDER BY a.id DESC LIMIT 100" 
);
?>

<div class="wrap sitecure-wrap">

	<div class="sitecure-header">
		<div class="sitecure-title-area">
			<h1><span class="dashicons dashicons-list-view"></span> Incident & Audit Log Trail</h1>
			<p>Immutable audit trail of all diagnostic scans, threat quarantines, core restorations, and operator actions.</p>
		</div>
	</div>

	<div class="wpd-card">
		<div class="wpd-card-body" style="padding: 0;">
			<?php if ( empty( $logs ) ) : ?>
				<div style="padding: 50px 20px; text-align: center; color: var(--wpd-text-muted);">
					<span class="dashicons dashicons-clipboard" style="font-size: 46px; width: 46px; height: 46px; color: var(--wpd-primary); margin-bottom: 12px;"></span>
					<h3 style="color: var(--wpd-text-main); margin: 0 0 6px 0;">No Audit Events Recorded</h3>
					<p style="margin: 0; font-size: 13px;">Actions will be permanently logged here as you run scans, quarantine files, or repair items.</p>
				</div>
			<?php else : ?>
				<table class="wpd-table">
					<thead>
						<tr>
							<th>Date / Time</th>
							<th>Site</th>
							<th>Action</th>
							<th>Target</th>
							<th>Details</th>
							<th>IP Address</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $logs as $l ) : ?>
							<tr>
								<td><code style="font-size: 11px;"><?php echo esc_html( $l->created_at ); ?></code></td>
								<td>
									<span class="wpd-badge" style="background: #e0f2fe; color: #0284c7; border-color: #bae6fd;">
										<?php echo esc_html( $l->site_name ? $l->site_name : 'System' ); ?>
									</span>
								</td>
								<td><span class="wpd-badge"><?php echo esc_html( strtoupper( $l->action ) ); ?></span></td>
								<td><strong style="color: var(--wpd-text-main);"><?php echo esc_html( $l->target_item ); ?></strong></td>
								<td style="color: var(--wpd-text-muted);"><?php echo esc_html( $l->details ); ?></td>
								<td><code><?php echo esc_html( $l->ip_address ? $l->ip_address : '127.0.0.1' ); ?></code></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
	</div>

</div>

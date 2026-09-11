<?php
/**
 * WP Doctor Quarantine Vault View
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Auto-sync any cleaned findings that don't have vault rows yet
if ( function_exists( 'wpdoctor_sync_cleaned_findings_to_vault' ) ) {
	wpdoctor_sync_cleaned_findings_to_vault();
}

global $wpdb;
$table_quarantine = wpdoctor_get_table( 'quarantine' );
$table_sites      = wpdoctor_get_table( 'sites' );

$items = $wpdb->get_results( "
	SELECT q.*, s.name as site_name 
	FROM $table_quarantine q 
	LEFT JOIN $table_sites s ON q.site_id = s.id 
	WHERE q.original_path NOT LIKE '%sitecure%' AND q.original_path NOT LIKE '%wp-doctor%' 
	ORDER BY q.id DESC" 
);
?>

<div class="wrap wpdoctor-wrap">

	<div class="wpdoctor-header">
		<div class="wpdoctor-title-area">
			<h1><span class="dashicons dashicons-lock"></span> Quarantine Storage Vault</h1>
			<p>Secure isolated repository protected by execution-denial directives. Recover or rollback any quarantined or cleaned item anytime.</p>
		</div>
	</div>

	<div class="wpd-card">
		<div class="wpd-card-body" style="padding: 0;">
			<?php if ( empty( $items ) ) : ?>
				<div style="padding: 50px 20px; text-align: center; color: var(--wpd-text-muted);">
					<span class="dashicons dashicons-unlock" style="font-size: 46px; width: 46px; height: 46px; color: var(--wpd-primary); margin-bottom: 12px;"></span>
					<h3 style="color: var(--wpd-text-main); margin: 0 0 6px 0;">Quarantine Vault is Empty</h3>
					<p style="margin: 0; font-size: 13px;">No threats have been quarantined or cleaned yet. When you clean or quarantine a threat, an isolated backup is safely preserved here.</p>
				</div>
			<?php else : ?>
				<table class="wpd-table">
					<thead>
						<tr>
							<th>Location / Threat Target</th>
							<th>SHA256 Hash</th>
							<th>Reason / Detection</th>
							<th>Quarantined / Cleaned At</th>
							<th>Status</th>
							<th style="text-align: right;">Action</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $items as $item ) : ?>
							<tr>
								<td>
									<strong style="color: var(--wpd-text-main); font-size: 13px;"><?php echo esc_html( $item->original_path ); ?></strong>
									<?php if ( ! empty( $item->site_name ) ) : ?>
										<span class="wpd-badge" style="background: #e0f2fe; color: #0284c7; border-color: #bae6fd; font-size: 11px; margin-left: 6px;">
											<?php echo esc_html( $item->site_name ); ?>
										</span>
									<?php endif; ?>
								</td>
								<td><code style="font-size: 11px;"><?php echo esc_html( substr( $item->original_hash, 0, 16 ) ); ?>...</code></td>
								<td style="max-width: 260px;"><?php echo esc_html( wp_trim_words( $item->reason, 8 ) ); ?></td>
								<td><?php echo esc_html( $item->created_at ); ?></td>
								<td>
									<?php
									$tag_class = 'healthy';
									if ( $item->status === 'quarantined' ) {
										$tag_class = 'critical';
									} elseif ( $item->status === 'cleaned' ) {
										$tag_class = 'cleaned';
									} elseif ( $item->status === 'restored' ) {
										$tag_class = 'healthy';
									}
									?>
									<span class="wpd-tag wpd-tag-<?php echo esc_attr( $tag_class ); ?>">
										<?php echo esc_html( strtoupper( $item->status ) ); ?>
									</span>
								</td>
								<td style="text-align: right;">
									<?php if ( in_array( $item->status, array( 'quarantined', 'cleaned' ), true ) ) : ?>
										<button class="wpd-btn wpd-btn-secondary wpd-btn-sm wpd-btn-restore" data-id="<?php echo (int) $item->id; ?>" title="Safely restore original content back to site">
											<span class="dashicons dashicons-undo" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle;"></span> 1-Click Restore
										</button>
									<?php else : ?>
										<span style="color: var(--wpd-emerald); font-size: 12px; font-weight: 600;">Restored at <?php echo esc_html( $item->restored_at ? $item->restored_at : $item->created_at ); ?></span>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
	</div>

</div>

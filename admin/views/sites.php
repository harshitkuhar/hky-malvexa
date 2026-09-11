<?php
/**
 * SiteCure Managed Sites View
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$sites        = sitecure_get_sites();
$is_dev       = sitecure_is_dev_mode();
$quota        = sitecure_get_site_quota();
$can_add      = sitecure_can_add_site();
$active_count = count( $sites );
?>

<div class="wrap sitecure-wrap">

	<div class="sitecure-header">
		<div class="sitecure-title-area">
			<h1><span class="dashicons dashicons-networking"></span> Managed WordPress Sites</h1>
			<p>Configure local or remote WordPress sites for diagnosis, malware cleaning, and health monitoring.</p>
		</div>
		<div class="sitecure-header-actions" style="display: flex; align-items: center; gap: 10px;">
			<?php if ( $is_dev ) : ?>
				<span class="wpd-badge" style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: 600;">
					<span class="dashicons dashicons-superhero" style="font-size: 14px; vertical-align: middle; margin-right: 2px;"></span> Developer Unlimited Access
				</span>
				<button type="button" id="wpd-btn-deactivate-license" class="wpd-btn wpd-btn-secondary wpd-btn-sm" style="font-size: 11px; padding: 4px 10px; border-radius: 20px; color: #64748b;" title="Deactivate License and return to Free plan">
					<span class="dashicons dashicons-dismiss" style="font-size: 13px; width: 13px; height: 13px; vertical-align: middle; margin-right: 2px;"></span> Deactivate Key
				</button>
			<?php else : ?>
				<span class="wpd-badge" style="background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: 600;">
					<span class="dashicons dashicons-admin-site" style="font-size: 14px; vertical-align: middle; margin-right: 2px;"></span> Free Plan: <?php echo (int) $active_count; ?>/1 Site Active
				</span>
				<button type="button" class="wpd-btn-open-pro-modal" style="background: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%); color: #fff; border: none; border-radius: 20px; font-weight: 600; font-size: 11px; padding: 5px 12px; cursor: pointer; box-shadow: 0 2px 6px rgba(79,70,229,0.3);">
					<span class="dashicons dashicons-star-filled" style="font-size: 13px; width: 13px; height: 13px; vertical-align: middle; margin-right: 2px;"></span> Upgrade to Pro
				</button>
			<?php endif; ?>

			<button id="wpd-btn-show-add-site" class="wpd-btn wpd-btn-primary" data-can-add="<?php echo $can_add ? '1' : '0'; ?>">
				<span class="dashicons dashicons-plus-alt2"></span> Add New Site
			</button>
		</div>
	</div>

	<?php if ( ! $is_dev && $active_count >= 1 ) : ?>
		<!-- Pro Multi-Site Banner -->
		<div style="margin-bottom: 20px; padding: 16px 20px; background: linear-gradient(135deg, #eff6ff 0%, #f0fdf4 100%); border: 1px solid #bfdbfe; border-radius: 10px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
			<div>
				<h3 style="margin: 0 0 4px 0; font-size: 15px; color: #1e3a8a; display: flex; align-items: center; gap: 6px;">
					<span class="dashicons dashicons-star-filled" style="color: #6366f1;"></span>
					Managing Multiple Websites or Client Sites?
				</h3>
				<p style="margin: 0; font-size: 13px; color: #475569;">
					The Free plan covers <strong>1 active target website</strong>. If you want to connect, scan, and clean multiple client websites from this single dashboard, upgrade to SiteCure Pro.
				</p>
			</div>
			<button type="button" class="wpd-btn-open-pro-modal" style="background: #4f46e5; color: #fff; border: none; padding: 9px 18px; font-size: 13px; font-weight: 600; border-radius: 6px; cursor: pointer; box-shadow: 0 2px 4px rgba(79,70,229,0.25);">
				Unlock Unlimited Client Sites
			</button>
		</div>
	<?php endif; ?>

	<?php if ( empty( $sites ) ) : ?>
		<!-- Onboarding: Choose Site #1 (Local Hosted Site OR External Client Site) -->
		<div style="margin-bottom: 24px; padding: 24px; background: #ffffff; border: 1px solid var(--wpd-card-border); border-radius: 12px; box-shadow: var(--wpd-shadow);">
			<div style="text-align: center; max-width: 600px; margin: 0 auto 24px auto;">
				<h2 style="margin: 0 0 8px 0; font-size: 18px; color: var(--wpd-text-main);">Welcome to SiteCure! Choose Your First Site Target</h2>
				<p style="margin: 0; font-size: 13px; color: var(--wpd-text-muted);">
					Your Free plan includes <strong>1 Active Target Website</strong>. You can use it to scan this hosted installation or connect an external client website.
				</p>
			</div>

			<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px;">
				<!-- Choice A: Scan This Hosted Website -->
				<div style="padding: 22px; border: 2px solid #e2e8f0; border-radius: 10px; background: #f8fafc; display: flex; flex-direction: column; justify-content: space-between;">
					<div>
						<div style="width: 42px; height: 42px; border-radius: 8px; background: #e0f2fe; color: #0284c7; display: flex; align-items: center; justify-content: center; margin-bottom: 12px;">
							<span class="dashicons dashicons-admin-site" style="font-size: 24px; width: 24px; height: 24px;"></span>
						</div>
						<h3 style="margin: 0 0 6px 0; font-size: 16px; color: var(--wpd-text-main);">Scan This Hosted Website</h3>
						<p style="margin: 0 0 14px 0; font-size: 13px; color: var(--wpd-text-muted);">
							1-Click setup to scan and protect this current WordPress site: <br>
							<code style="font-size: 11.5px;"><?php echo esc_html( home_url() ); ?></code>
						</p>
					</div>
					<button type="button" id="wpd-btn-register-local" class="wpd-btn wpd-btn-primary" style="justify-content: center;">
						<span class="dashicons dashicons-controls-play"></span> Use Free Slot for This Site
					</button>
				</div>

				<!-- Choice B: Connect External Client Site -->
				<div style="padding: 22px; border: 2px solid #e2e8f0; border-radius: 10px; background: #f8fafc; display: flex; flex-direction: column; justify-content: space-between;">
					<div>
						<div style="width: 42px; height: 42px; border-radius: 8px; background: #fef3c7; color: #d97706; display: flex; align-items: center; justify-content: center; margin-bottom: 12px;">
							<span class="dashicons dashicons-networking" style="font-size: 24px; width: 24px; height: 24px;"></span>
						</div>
						<h3 style="margin: 0 0 6px 0; font-size: 16px; color: var(--wpd-text-main);">Connect External / Client Site</h3>
						<p style="margin: 0 0 14px 0; font-size: 13px; color: var(--wpd-text-muted);">
							Connect a remote client WordPress site via local filesystem path or secure SFTP connection.
						</p>
					</div>
					<button type="button" id="wpd-btn-onboard-external" class="wpd-btn wpd-btn-secondary" style="justify-content: center;">
						<span class="dashicons dashicons-plus-alt2"></span> Connect Client Site
					</button>
				</div>
			</div>
		</div>
	<?php endif; ?>

	<!-- Add Site Form Card (Hidden by default) -->
	<div id="wpd-add-site-card" class="wpd-card" style="display: none; border-color: var(--wpd-cyan); margin-bottom: 20px;">
		<div class="wpd-card-header">
			<h2 class="wpd-card-title"><span class="dashicons dashicons-plus"></span> Add Target WordPress Site</h2>
		</div>
		<div class="wpd-card-body">
			<form id="wpd-form-add-site">
				<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 18px;">
					<div>
						<label class="wpd-label">Site Name *</label>
						<input type="text" name="site_name" class="wpd-input" required placeholder="e.g. Client Production Site">
					</div>
					<div>
						<label class="wpd-label">Website URL *</label>
						<input type="url" name="site_url" class="wpd-input" required placeholder="https://example.com">
					</div>
					<div>
						<label class="wpd-label">Environment</label>
						<select name="environment" class="wpd-select">
							<option value="production">Production</option>
							<option value="staging">Staging</option>
							<option value="development">Development</option>
						</select>
					</div>
					<div>
						<label class="wpd-label">Access Mode</label>
						<select name="access_mode" class="wpd-select">
							<option value="sftp">Remote SFTP / SSH</option>
						</select>
					</div>
					<div>
						<label class="wpd-label">Server / Local Path (Optional if on same server)</label>
						<input type="text" name="wp_path" class="wpd-input" placeholder="e.g. ../betterdays or auto-detect">
					</div>
				</div>

				<!-- SFTP Details -->
				<div class="wpd-form-box">
					<h4 class="wpd-form-box-title">
						<span class="dashicons dashicons-lock" style="color: var(--wpd-primary); vertical-align: middle;"></span>
						SFTP Connection Details (Encrypted at Rest with AES-256)
					</h4>
					<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px;">
						<div>
							<label class="wpd-label">SFTP Host / IP</label>
							<input type="text" name="sftp_host" class="wpd-input" placeholder="sftp.example.com">
						</div>
						<div>
							<label class="wpd-label">Port</label>
							<input type="number" name="sftp_port" class="wpd-input" value="22">
						</div>
						<div>
							<label class="wpd-label">Username</label>
							<input type="text" name="sftp_user" class="wpd-input" placeholder="ssh_user">
						</div>
						<div>
							<label class="wpd-label">Password / Key</label>
							<input type="password" name="sftp_pass" class="wpd-input" placeholder="••••••••">
						</div>
						<div>
							<label class="wpd-label">Remote WordPress Path</label>
							<input type="text" name="sftp_path" class="wpd-input" value="/public_html">
						</div>
					</div>
				</div>

				<div style="display: flex; gap: 10px;">
					<button type="submit" class="wpd-btn wpd-btn-primary">Save Site Profile</button>
					<button type="button" class="wpd-btn wpd-btn-secondary" onclick="jQuery('#wpd-add-site-card').slideUp(200);">Cancel</button>
				</div>
			</form>
		</div>
	</div>

	<!-- Sites List -->
	<?php if ( ! empty( $sites ) ) : ?>
		<div class="wpd-card">
			<div class="wpd-card-header">
				<h2 class="wpd-card-title"><span class="dashicons dashicons-admin-site"></span> Registered Websites</h2>
			</div>
			<div class="wpd-card-body" style="padding: 0;">
				<table class="wpd-table">
					<thead>
						<tr>
							<th>Site Name</th>
							<th>URL</th>
							<th>Environment</th>
							<th>Access Mode</th>
							<th>Health Status</th>
							<th>Last Scan</th>
							<th style="text-align: right;">Actions</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $sites as $s ) : ?>
							<tr>
								<td><strong><?php echo esc_html( $s->name ); ?></strong></td>
								<td><a href="<?php echo esc_url( $s->url ); ?>" target="_blank" style="color: var(--wpd-cyan); text-decoration: none;"><?php echo esc_html( $s->url ); ?></a></td>
								<td><code><?php echo esc_html( strtoupper( $s->environment ) ); ?></code></td>
								<td><span class="wpd-badge"><?php echo esc_html( strtoupper( $s->access_mode ) ); ?></span></td>
								<td>
									<span class="wpd-tag wpd-tag-<?php echo ( $s->health_status === 'healthy' ) ? 'healthy' : ( ( $s->health_status === 'compromised' ) ? 'critical' : 'high' ); ?>">
										<?php echo esc_html( strtoupper( $s->health_status ) ); ?>
									</span>
								</td>
								<td><?php echo esc_html( $s->last_scan ? $s->last_scan : 'Never' ); ?></td>
								<td style="text-align: right;">
									<div style="display: inline-flex; gap: 6px; align-items: center; justify-content: flex-end;">
										<a href="<?php echo esc_url( admin_url( 'admin.php?page=sitecure-findings&site_id=' . $s->id ) ); ?>" class="wpd-btn wpd-btn-primary wpd-btn-sm">
											<span class="dashicons dashicons-shield" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle;"></span> Scan & Findings
										</a>
										<button type="button" class="wpd-btn wpd-btn-secondary wpd-btn-sm wpd-btn-delete-site" data-id="<?php echo (int) $s->id; ?>" data-name="<?php echo esc_attr( $s->name ); ?>" title="Remove this site to free up your slot">
											<span class="dashicons dashicons-trash" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle; color: #ef4444;"></span>
										</button>
									</div>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
	<?php endif; ?>

</div>

<!-- Pro Upgrade / Multi-Site Modal -->
<div id="wpd-pro-upgrade-modal" class="wpd-modal-backdrop">
	<div class="wpd-modal" style="max-width: 540px;">
		<div class="wpd-modal-header" style="background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); color: #fff; border-top-left-radius: 13px; border-top-right-radius: 13px; border-bottom: none;">
			<div>
				<h3 class="wpd-modal-title" style="color: #fff; display: flex; align-items: center; gap: 8px;">
					<span class="dashicons dashicons-star-filled" style="color: #fbbf24;"></span>
					SiteCure Pro — Multi-Site & Client Hub
				</h3>
				<div style="font-size: 12px; color: #c7d2fe; margin-top: 3px;">
					Manage & clean unlimited WordPress websites from one dashboard.
				</div>
			</div>
			<button type="button" class="wpd-modal-close" style="color: #fff;" aria-label="Close">&times;</button>
		</div>
		<div class="wpd-modal-body" style="padding: 22px;">
			<div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px;">
				<strong style="color: #1e40af; font-size: 13px;">Free Plan Limit Reached (1 Active Site)</strong>
				<p style="margin: 4px 0 0 0; font-size: 12.5px; color: #3b82f6;">
					Your Free plan covers 1 active website. To add client sites or manage multiple domains simultaneously, upgrade to SiteCure Pro.
				</p>
			</div>

			<h4 style="margin: 0 0 10px 0; font-size: 13px; color: #0f172a;">Everything included in SiteCure Pro:</h4>
			<ul style="margin: 0 0 18px 0; padding-left: 20px; font-size: 12.5px; color: #475569; line-height: 1.8;">
				<li><strong>Unlimited Websites & Client Portfolios:</strong> Manage 10, 50, or 100+ client sites from one screen.</li>
				<li><strong>Zero Host Server Bloat:</strong> Backups stay isolated on each client's server.</li>
				<li><strong>Automated Background Scanning:</strong> Real-time zero-day threat detection.</li>
				<li><strong>Agency Client Reports:</strong> Export clean PDF health audits for clients.</li>
			</ul>

			<!-- Early Access / Waitlist Form -->
			<div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 16px;">
				<label style="display: block; font-weight: 600; font-size: 12px; color: #1e293b; margin-bottom: 6px;">
					Request Early VIP Pro Access / Join Waitlist:
				</label>
				<div style="display: flex; gap: 8px;">
					<input type="email" id="wpd-pro-email" class="wpd-input" placeholder="you@agency.com" value="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" style="font-size: 12.5px;">
					<button type="button" id="wpd-btn-join-pro" class="wpd-btn wpd-btn-primary" style="white-space: nowrap; font-size: 12px;">
						Join Waitlist
					</button>
				</div>
				<div id="wpd-pro-waitlist-msg" style="display: none; margin-top: 8px; font-size: 12px; color: #059669; font-weight: 600;"></div>
			</div>

			<!-- License Key Input (For Developer / Paid Users) -->
			<div style="border-top: 1px dashed #cbd5e1; padding-top: 14px;">
				<label style="display: block; font-weight: 600; font-size: 12px; color: #475569; margin-bottom: 6px;">
					Already have a Pro or Developer License Key?
				</label>
				<div style="display: flex; gap: 8px;">
					<input type="text" id="wpd-license-key" class="wpd-input" placeholder="Enter your SiteCure Pro license key" style="font-size: 12.5px; font-family: monospace;">
					<button type="button" id="wpd-btn-activate-license" class="wpd-btn wpd-btn-secondary" style="white-space: nowrap; font-size: 12px;">
						Activate Key
					</button>
				</div>
				<div id="wpd-license-status-msg" style="display: none; margin-top: 8px; font-size: 12px;"></div>
			</div>
		</div>
	</div>
</div>


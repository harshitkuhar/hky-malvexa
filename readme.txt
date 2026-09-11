=== SiteCure – Malware Scanner, Spam Cleaner & Security Vault ===
Contributors: harshitkuhar
Donate link: https://github.com/harshitkuhar
Tags: malware scanner, security, clean malware, seo spam, quarantine
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Surgical WordPress malware scanner, blackhat SEO & casino spam cleaner, core integrity restorer, and isolated quarantine storage vault with 1-click rollback.

== Description ==

**SiteCure** is a professional-grade WordPress security platform designed for emergency diagnosis, malware investigation, surgical threat neutralization, and recovery.

Unlike generic security plugins that overwhelm your dashboard with complex configuration settings or lock you out of your own site, SiteCure focuses on **surgical threat detection and immediate recovery**:

* **Zero-Timeout Batched Scanning**: Process large file structures and heavy databases without server timeouts, memory exhaustion, or 504 Gateway errors.
* **Blackhat SEO & Casino Spam Cleaner**: Detects and cleans hidden Japanese keywords, casino/gambling redirects, cloaked spam links, and obfuscated iframes from post contents and Elementor/Gutenberg metadata without corrupting page layouts.
* **Surgical Code Neutralization**: Neutralizes backdoors, web shells (FilesMan, WSO, b374k), and eval-injected PHP headers safely while leaving legitimate theme and plugin files operational.
* **Isolated Quarantine Storage Vault**: When a threat is quarantined or cleaned, a secure timestamped safety backup is created in a protected storage vault (`.htaccess` blocked) with 1-click instant file and database rollback.
* **WordPress Core Integrity Verification**: Checksums your core files against official WordPress.org cryptographic hashes and provides 1-click core repair to replace altered files with pristine originals directly from the official WordPress repository.
* **Immutable Incident & Audit Trail**: Every scan execution, threat quarantine, core restore, and operator action is recorded in a tamper-resistant local audit log.

### Key Features

1. **Integrated Emergency Scanner**:
   - Quick Scan: Rapidly inspects active plugins, theme headers, wp-config.php, index.php, and database options.
   - Deep Scan: Comprehensive multi-stage file and database examination across all folders, uploads, and posts.
2. **Interactive Threat Inspector**:
   - Live code preview box showing exact line numbers and malicious syntax highlighted.
   - 1-click action buttons: "Clean the File", "Quarantine File", "Repair from WordPress.org", or "Clean Spam from Page".
3. **Database Spam Detection**:
   - Scans `wp_posts` for cloaked links and off-screen negative-margin spam text.
   - Scans `wp_options` and `wpcode` database snippets for rogue script tags and base64 payloads.
   - Scans `wp_users` for stealth rogue administrator accounts.
4. **Isolated Vault & 1-Click Rollback**:
   - Quarantined files are neutralized and moved outside the public web root with PHP execution disabled.
   - 1-click restore instantly writes the pristine backup back to disk or recovers the original post content.
5. **Multi-Site Portfolio Ready**:
   - Free plan includes 1 active target site.
   - Connect client websites via local filesystem paths or secure SFTP connections for agency management.

== Installation ==

1. Upload the `sitecure` folder to the `/wp-content/plugins/` directory, or install the ZIP file via **Plugins > Add New > Upload Plugin**.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **SiteCure** in your WordPress admin menu to access your Dashboard.
4. Click **Start Emergency Scan** to immediately inspect your website for threats and malware.

== Frequently Asked Questions ==

= Does SiteCure modify or delete files without permission? =
No. SiteCure never modifies or deletes any file without your explicit action. When you choose to quarantine or clean an infected file, SiteCure creates a timestamped safety backup in an isolated storage vault before making any changes.

= Can I restore a quarantined file if it causes an issue? =
Yes. Navigate to **SiteCure > Quarantine Vault** or the **Scan & Findings** screen. Any quarantined file or cleaned database snippet can be restored to its exact original location with a single click.

= How does the Blackhat SEO spam cleaner work? =
Attackers often inject spam links, hidden gambling keywords (e.g. slot88, casino, sbobet), or hidden off-screen divs (`position:absolute;left:-9999px`) into your post contents or Elementor data. SiteCure surgically strips out the malicious markup and restores your original content without breaking your page layout or styling.

= What is Core Integrity Repair? =
SiteCure downloads official cryptographic checksums from the WordPress.org API for your exact WordPress version. If any core file (e.g. `wp-login.php`, `wp-settings.php`, `wp-includes/`) has been modified by malware, you can replace it with a pristine official copy from WordPress.org with one click.

= Does SiteCure connect to external cloud services? =
SiteCure is fully operational standalone on your server. For multi-site management and license validation, SiteCure optionally connects to the SiteCure Cloud Verification microservice to verify domain quotas and active plan status.

== Screenshots ==

1. **Dashboard & Threat Overview**: Real-time health metrics, active threat counts, and quick scanner launcher.
2. **Scan Center & Live Execution**: Zero-timeout batched scanner with live terminal logs and progress tracking.
3. **Threat Findings & Evidence**: Detailed catalog of detected malware, backdoors, and SEO spam with severity badges.
4. **Interactive Code Inspector**: Preview infected code with exact line markers and 1-click remediation actions.
5. **Quarantine Storage Vault**: Isolated, `.htaccess`-protected storage vault with 1-click rollback.
6. **Managed Sites Portfolio**: Multi-site portfolio manager supporting local and client WordPress sites.

== Changelog ==

= 1.0.0 =
* Initial public release on WordPress.org.
* Zero-timeout chunked batched file and database scanning engine.
* Blackhat SEO and casino spam surgical extraction pipeline.
* Official WordPress.org core checksum comparison and 1-click file repair.
* Isolated quarantine storage vault with 1-click rollback.
* Tamper-resistant incident audit log.

<?php
/**
 * HKY MalVexa Managed Sites View (Redirector)
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

wp_safe_redirect( admin_url( 'admin.php?page=hkymalvexa-findings' ) );
exit;

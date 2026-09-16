<?php
/**
 * HKY MalVexa Malware Signatures & High-Confidence Detection Rules
 * Pure Core PHP procedural definition
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Returns verified high-confidence malware patterns
 */
function hkymalvexa_get_malware_rules() {
	return array(
		// 1. Classic Webshell signatures
		array(
			'id'             => 'WS_WSO_WEBSHELL',
			'name'           => 'WSO / FilesMan Webshell',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 99,
			'pattern'        => '/(FilesMan|WSO_VERSION|default_use_ajax|default_action\s*=\s*[\'"]FilesMan[\'"])/i',
			'description'    => 'Detected signatures of the WSO / FilesMan PHP Webshell backdoor.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'WS_C99_R57',
			'name'           => 'c99 / r57 Webshell',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 99,
			'pattern'        => '/(c99shell|r57shell|c99_sess_put|r57_sess_put)/i',
			'description'    => 'Detected signatures of known c99 / r57 webshell toolkit.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'WS_B374K',
			'name'           => 'b374k Webshell',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 99,
			'pattern'        => '/(b374k|eval\(gzinflate\(base64_decode\(b374k)/i',
			'description'    => 'Detected b374k webshell backdoor.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'WS_ALFA',
			'name'           => 'Alfa Team Webshell',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 99,
			'pattern'        => '/(Alfa\s+Team|alfa_shell|Sole visible backdoor)/i',
			'description'    => 'Detected Alfa Team webshell backdoor.',
			'action'         => 'quarantine',
		),

		// 2. High-Confidence Obfuscated Execution
		array(
			'id'             => 'OBF_BASE64_EVAL',
			'name'           => 'eval(base64_decode()) Payload',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 98,
			'pattern'        => '/eval\s*\(\s*base64_decode\s*\(/i',
			'description'    => 'Direct execution of base64-decoded code string. High confidence backdoor loader.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'OBF_GZ_BASE64_EVAL',
			'name'           => 'Obfuscated Eval Gzinflate Payload',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/eval\s*\(\s*(?:gzinflate|gzuncompress|bzdecompress)\s*\(\s*base64_decode\s*\(/i',
			'description'    => 'Classic multi-layer obfuscation wrapper executing hidden arbitrary code.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'OBF_STR_ROT13_EVAL',
			'name'           => 'Obfuscated str_rot13 Eval',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/eval\s*\(\s*str_rot13\s*\(\s*(?:base64_decode)?/i',
			'description'    => 'ROT13 obfuscation combined with dynamic code execution.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'DYN_PREG_REPLACE_E',
			'name'           => 'preg_replace /e Code Execution',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/preg_replace\s*\(\s*[\'"].*\/e[\'"]\s*,/i',
			'description'    => 'Deprecated and dangerous regex evaluate modifier (/e) executing arbitrary input.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'DYN_ASSERT_PAYLOAD',
			'name'           => 'assert() Dynamic Execution',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 90,
			'pattern'        => '/assert\s*\(\s*(?:\$_(?:POST|GET|REQUEST|COOKIE)|base64_decode)/i',
			'description'    => 'Direct user payload or base64 string passed to assert() for code execution.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'DYN_CREATE_FUNCTION',
			'name'           => 'create_function() Backdoor Invoker',
			'severity'       => 'high',
			'classification' => 'malicious',
			'confidence'     => 85,
			'pattern'        => '/create_function\s*\(\s*[\'"][^\'"]*[\'"]\s*,\s*(?:\$_(?:POST|GET|REQUEST|COOKIE)|base64_decode)/i',
			'description'    => 'Arbitrary user input passed into dynamic lambda creation.',
			'action'         => 'quarantine',
		),

		// 3. User Payload Dynamic Invocation
		array(
			'id'             => 'DYN_VARIABLE_FUNCTION_INJECTION',
			'name'           => 'Dynamic Variable Function Injection',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 92,
			'pattern'        => '/(?:\$_(?:POST|GET|REQUEST|COOKIE)\[[^\]]+\])\s*\(\s*(?:\$_(?:POST|GET|REQUEST|COOKIE)|base64_decode)/i',
			'description'    => 'HTTP request parameter used as function name calling another user parameter.',
			'action'         => 'quarantine',
		),
		array(
			'id'             => 'DYN_GLOBALS_OVERWRITE_EXEC',
			'name'           => 'GLOBALS Array Code Execution',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 90,
			'pattern'        => '/\$GLOBALS\s*\[\s*(?:\$_(?:POST|GET|REQUEST)|[a-zA-Z0-9_\-\$]+)\s*\]\s*\(\s*\$_(?:POST|GET|REQUEST)/i',
			'description'    => 'Arbitrary function execution via dynamic $GLOBALS array lookup.',
			'action'         => 'quarantine',
		),

		// 4. Rogue Administrator Creation in stealth files
		array(
			'id'             => 'ROGUE_ADMIN_CREATOR',
			'name'           => 'Stealth WordPress Administrator Injector',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 90,
			'pattern'        => '/(?:wp_create_user|wp_insert_user)\s*\([^;]{1,250}[\'"]administrator[\'"]/i',
			'description'    => 'Code automatically creating administrator users from non-standard files.',
			'action'         => 'quarantine',
		),

		// 5. Malicious file writing from remote inputs
		array(
			'id'             => 'FILE_PUT_CONTENTS_REMOTE_DROPPER',
			'name'           => 'Remote Dropper / File Injector',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 88,
			'pattern'        => '/file_put_contents\s*\(\s*[^,]+,\s*(?:file_get_contents|curl_exec)\s*\(/i',
			'description'    => 'Directly downloading remote payload and writing to local server filesystem.',
			'action'         => 'quarantine',
		),

		// 6. Stealth Non-PHP Extension File Includers (Fake .ico / .tmp / .dat loaders)
		array(
			'id'             => 'INJ_STEALTH_INCLUDE',
			'name'           => 'Stealth Non-PHP File Includer',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/(?:^|[\s;{}])@?(?:include|require)(?:_once)?\s*\(?[^;\r\n]{0,80}[\'"][^\'"]*\.(?:ico|tmp|cache|dat|sess)[\'"]\s*\)?/i',
			'description'    => 'Code including non-PHP extensions (e.g. .ico, .tmp, .dat) commonly used by backdoor droppers to execute hidden payloads.',
			'action'         => 'clean',
		),

		// 7. Dynamic Callback User Input Execution (call_user_func)
		array(
			'id'             => 'DYN_CALL_USER_FUNC_INPUT',
			'name'           => 'Dynamic Callback User Input Execution',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/call_user_func(?:_array)?\s*\(\s*(?:\$_(?:POST|GET|REQUEST|COOKIE)|base64_decode)/i',
			'description'    => 'User-controlled input directly executed via call_user_func callback.',
			'action'         => 'clean',
		),

		// 8. Variable Variable Dynamic Execution ($$var)
		array(
			'id'             => 'DYN_VARIABLE_EXECUTION',
			'name'           => 'Variable Variable Dynamic Execution',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 92,
			'pattern'        => '/\$\$\w+\s*\(\s*(?:\$_(?:POST|GET|REQUEST|COOKIE)|base64_decode)/i',
			'description'    => 'Variable function dynamic invocation executing arbitrary user input.',
			'action'         => 'clean',
		),

		// 9. Persistent Auto-Creation of Admin User on init
		array(
			'id'             => 'ROGUE_ADMIN_INIT_HOOK',
			'name'           => 'Rogue Administrator Auto-Creation Hook',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 94,
			'pattern'        => '/add_action\s*\(\s*[\'"](?:init|admin_init|wp_loaded)[\'"][^;]+(?:wp_create_user|wp_insert_user|administrator)/i',
			'description'    => 'Persistent action hook creating administrator user automatically on website visit.',
			'action'         => 'clean',
		),

		// 10. Hex-packed binary decode execution (pack("H*"))
		array(
			'id'             => 'OBF_PACK_HEX_EVAL',
			'name'           => 'pack("H*") Hex Execution Payload',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 96,
			'pattern'        => '/eval\s*\(\s*(?:pack|unpack)\s*\(\s*[\'"]H\*[\'"]/i',
			'description'    => 'Hex-packed binary decoded directly into dynamic eval code execution.',
			'action'         => 'clean',
		),

		// 11. Long Encoded Base64 Eval Loader
		array(
			'id'             => 'OBF_RAW_BASE64_LONG_EVAL',
			'name'           => 'Long Encoded Base64 Eval Loader',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/eval\s*\(\s*base64_decode\s*\(\s*[\'"][a-zA-Z0-9+\/=\s]{60,}[\'"]\s*\)\s*\)/i',
			'description'    => 'Direct execution of hardcoded obfuscated base64 encoded PHP payload.',
			'action'         => 'clean',
		),

		// 12. Remote Code Fetcher & Dynamic Eval
		array(
			'id'             => 'REMOTE_EXEC_FETCHER',
			'name'           => 'Remote Code Fetch & Dynamic Eval',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 94,
			'pattern'        => '/eval\s*\(\s*(?:file_get_contents|curl_exec|wp_remote_get)\s*\(/i',
			'description'    => 'Direct execution of remotely fetched code from external URL.',
			'action'         => 'clean',
		),

		// 13. Stealth Authentication Cookie Bypass
		array(
			'id'             => 'BACKDOOR_AUTH_BYPASS',
			'name'           => 'Authentication Cookie Bypass Backdoor',
			'severity'       => 'critical',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/wp_set_current_user\s*\(\s*\d+\s*\)\s*;\s*wp_set_auth_cookie/i',
			'description'    => 'Direct login bypass forcing user authentication without password.',
			'action'         => 'clean',
		),

		// 14. Blackhat SEO Cloaked Spam & Link Injections
		array(
			'id'             => 'SPAM_CLOAKED_OFFSCREEN_DIV',
			'name'           => 'Cloaked Off-Screen SEO Spam Injection',
			'severity'       => 'high',
			'classification' => 'malicious',
			'confidence'     => 98,
			'pattern'        => '/(?:data-wp-poster\s*=\s*[\'"][a-f0-9]{16,}[\'"]|<(?:div|p|span)[^>]*style\s*=\s*[\'"][^\'"]*(?:left|top|margin-left|text-indent)\s*:\s*-\d{4,}px[^\'"]*[\'"][^>]*>.*?<a\s+href)/is',
			'description'    => 'Detected hidden off-screen cloaked spam container with outbound links (parasite SEO / casino / gambling injection).',
			'action'         => 'clean',
		),
		array(
			'id'             => 'SPAM_CASINO_LINK_FARM',
			'name'           => 'Injected Casino / Gambling Spam Link Farm',
			'severity'       => 'high',
			'classification' => 'malicious',
			'confidence'     => 95,
			'pattern'        => '/(?:data-wp-poster|position\s*:\s*absolute\s*;\s*left\s*:\s*-\d{3,}).*?(?:kasyno|kaszin[oó]|casino|wazamba|spinanga|cazimbo|vegasino|gransino|spinsy|spielautomaten|highflybet|funbet|casinia|liraspin)/is',
			'description'    => 'Automated casino affiliate spam injection detected with cloaked anchor text links.',
			'action'         => 'clean',
		),

		// 15. Harmless Diagnostic Test String (For Safe Testing & QA)
		array(
			'id'             => 'HKYMALVEXA_TEST_SIGNATURE',
			'name'           => 'HKY MalVexa Diagnostic Test String (Safe QA Test)',
			'severity'       => 'low',
			'classification' => 'suspicious',
			'confidence'     => 100,
			'pattern'        => '/(?:HKYMALVEXA_SAFE_|HKYMALVEXA_SAFE_)?TEST_STRING_DO_NOT_ALARM/i',
			'description'    => 'Harmless diagnostic test marker for safely testing scanner detection, quarantine, and cleaning pipeline.',
			'action'         => 'clean',
		),
	);
}

/**
 * Returns suspicious heuristic patterns requiring review
 */
function hkymalvexa_get_heuristics() {
	return array(
		array(
			'id'             => 'SUSP_HEX_ENCODED_STRING_CASCADE',
			'name'           => 'Excessive Hex-Encoded Strings',
			'severity'       => 'medium',
			'classification' => 'suspicious',
			'confidence'     => 70,
			'pattern'        => '/(?:\\\\x[0-9a-fA-F]{2}){10,}/',
			'description'    => 'Concentration of hex-escaped byte sequences often used in obfuscated loaders.',
			'action'         => 'review',
		),
		array(
			'id'             => 'SUSP_CHR_CONCATENATION',
			'name'           => 'Chr() Character Concatenation Chain',
			'severity'       => 'medium',
			'classification' => 'suspicious',
			'confidence'     => 75,
			'pattern'        => '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}/i',
			'description'    => 'Long sequences of concatenated chr() numbers hiding function names or URLs.',
			'action'         => 'review',
		),
		array(
			'id'             => 'SUSP_SPAM_REDIRECT_KEYWORDS',
			'name'           => 'SEO / Casino / Pharma Redirect Keywords',
			'severity'       => 'high',
			'classification' => 'suspicious',
			'confidence'     => 80,
			'pattern'        => '/(wp_enqueue_script|document\.location|window\.location).*?(?:slot88|joker123|sbobet|viagra|cialis|online-casino|trafficjunky)/i',
			'description'    => 'Injected spam SEO redirects or gambling scripts detected.',
			'action'         => 'review',
		),
	);
}

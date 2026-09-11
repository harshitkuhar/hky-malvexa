<?php
/**
 * SiteCure Procedural Cryptography Helper
 * AES-256 encryption at rest for remote SFTP/SSH/DB credentials
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function sitecure_get_crypto_key() {
	$secret = defined( 'AUTH_KEY' ) ? AUTH_KEY : 'sitecure-fallback-key-salt-982143';
	return hash( 'sha256', $secret, true );
}

/**
 * Encrypt sensitive string
 */
function sitecure_encrypt( $plaintext ) {
	if ( empty( $plaintext ) ) {
		return '';
	}

	if ( ! function_exists( 'openssl_encrypt' ) ) {
		return base64_encode( $plaintext );
	}

	$method = 'aes-256-cbc';
	$key = sitecure_get_crypto_key();
	$iv_len = openssl_cipher_iv_length( $method );
	$iv = openssl_random_pseudo_bytes( $iv_len );

	$ciphertext = openssl_encrypt( $plaintext, $method, $key, OPENSSL_RAW_DATA, $iv );
	return base64_encode( $iv . $ciphertext );
}

/**
 * Decrypt sensitive string
 */
function sitecure_decrypt( $encrypted_base64 ) {
	if ( empty( $encrypted_base64 ) ) {
		return '';
	}

	if ( ! function_exists( 'openssl_decrypt' ) ) {
		return base64_decode( $encrypted_base64 );
	}

	$raw = base64_decode( $encrypted_base64 );
	$method = 'aes-256-cbc';
	$key = sitecure_get_crypto_key();
	$iv_len = openssl_cipher_iv_length( $method );

	if ( strlen( $raw ) < $iv_len ) {
		return '';
	}

	$iv = substr( $raw, 0, $iv_len );
	$ciphertext = substr( $raw, $iv_len );

	return openssl_decrypt( $ciphertext, $method, $key, OPENSSL_RAW_DATA, $iv );
}

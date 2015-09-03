<?php
/**
 * Plugin Name: WP REST API Key Authentication
 * Description: API/Secret Key Authentication handler for the WP REST API
 * Author: WP REST API Team
 * Author URI: http://wp-api.org
 * Version: 0.1.1
 * Plugin URI: https://github.com/WP-API/WP-API
 * License: GPL2+
 */

/**
 * Checks the HTTP request and authenticates a user using an API key and shared secret.
 *
 * @since    0.1.0
 * @param    mixed    $user    The current user passed in the filter.
 */

class JSON_Key_Auth {

	/**
	 * The primary handler for user authentication.
	 *
	 * @since     0.1.0
	 * @param     mixed    $user    The current user (or bool) passing through the filter.
	 * @return    mixed             A user on success, or false on failure.
	 */
	public static function authHandler( $user ) {

		// Don't authenticate twice
		if ( ! empty( $user ) ) {
			return $user;
		}

		if ( !isset( $_SERVER['HTTP_X_API_KEY'] ) ||
			 !isset( $_SERVER['HTTP_X_API_TIMESTAMP'] ) ||
			 !isset( $_SERVER['HTTP_X_API_SIGNATURE'] ) ) {
			return $user;
		}

		$user_id     = self::findUserIdByKey( $_SERVER['HTTP_X_API_KEY'] );
		$user_secret = get_user_meta( $user_id, 'json_shared_secret' );

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key'        => $_SERVER['HTTP_X_API_KEY'],
			'timestamp'      => $_SERVER['HTTP_X_API_TIMESTAMP'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_uri'    => $_SERVER['REQUEST_URI'],
		);

		$signature_gen = self::generateSignature( $signature_args, $user_secret );
		$signature     = $_SERVER['HTTP_X_API_SIGNATURE'];

		if ( $signature_gen !== $signature ) {
			return false;
		}

		return $user_id;
	}

	/**
	 * Generate signature.
	 *
	 * @since     0.1.0
	 * @param     array     $args      The arguments used for generating the signature. They should be, in order:
	 *                                 'api_key', 'timestamp', 'request_method', and 'request_uri'.
	 *                                 Timestamp should be the timestamp passed in the reques.
	 * @param     string    $secret    The shared secret we are using to generate the hash.
	 * @return    string
	 */
	public static function generateSignature( $args, $secret ) {
		return md5( json_encode( $args ) . $secret );
	}

	/**
	 * Fetches a user ID by API key.
	 *
	 * @since     0.1.0
	 * @param     string    $api_key    The API key attached to a user.
	 * @return    bool
	 */
	public static function findUserIdByKey( $api_key ) {

		$user_args = array(
			'meta_query' => array(
				array(
					'key'   => 'json_api_key',
					'value' => $api_key,
				),
			),
			'number'     => 1,
			'fields'     => array( 'ID' ),
		);

		$user = get_users( $user_args );
		if ( is_array( $user ) && !empty( $user ) ) {
			return $user[0]->ID;
		}

		return false;
	}
}

add_filter( 'determine_current_user', array( 'JSON_Key_Auth', 'authHandler' ), 20 );

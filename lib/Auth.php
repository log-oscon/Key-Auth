<?php
/**
 * Authentication handler
 *
 * @link       http://log.pt/
 * @since      1.0.0
 *
 * @package    RESTKeyAuth
 * @subpackage RESTKeyAuth/lib
 */

namespace logoscon\RESTKeyAuth;

/**
 * Authentication handler.
 *
 * @package    RESTKeyAuth
 * @subpackage RESTKeyAuth/lib
 * @author     log.OSCON, Lda. <engenharia@log.pt>
 */
class Auth {

	/**
	 * Handles the user authentication.
	 *
	 * @since  1.0.0
	 * @param  int|bool $user_id User ID if one has been determined, false otherwise.
	 * @return int|bool          User ID if one has been determined, false otherwise.
	 */
	public static function handler( $user_id ) {

		// Don't authenticate twice
		if ( ! empty( $user_id ) ) {
			return $user_id;
		}

		// Check for request headers
		if ( ! static::check_request_headers() ) {
			return $user_id;
		}

		// Fetch user ID
		$user_id = static::find_user_id_by_key( $_SERVER['HTTP_X_API_KEY'] );

		if ( ! $user_id ) {
			static::set_response_headers( 'Invalid API KEY.' );
			return false;
		}

		// Check timestamp
		if ( ! static::valid_timestamp() ) {
			static::set_response_headers( 'Invalid timestamp.' );
			return false;
		}

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key'        => $_SERVER['HTTP_X_API_KEY'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_post'   => $_POST,
			'request_uri'    => $_SERVER['REQUEST_URI'],
			'timestamp'      => intval( $_SERVER['HTTP_X_API_TIMESTAMP'] ),
		);

		$user_secret = \get_user_meta( $user_id, 'rest_api_secret', true );
		$signature   = static::generate_signature( $signature_args, $user_secret );

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( var_export( $signature_args, true ) );
			error_log( var_export( $signature, true ) );
		}

		if ( $signature !== $_SERVER['HTTP_X_API_SIGNATURE'] ) {
			static::set_response_headers( 'Invalid API signature.' );
			return false;
		}

		// Set headers
		static::set_response_headers( 'OK' );

		return $user_id;
	}

	/**
	 * Checks for the presence of required request headers.
	 *
	 * @access private
	 * @since  1.0.0
	 * @return bool True if the request headers are present, false otherwise.
	 */
	private static function check_request_headers() {
		return
			isset( $_SERVER['HTTP_X_API_KEY'] ) &&
			isset( $_SERVER['HTTP_X_API_TIMESTAMP'] ) &&
			isset( $_SERVER['HTTP_X_API_SIGNATURE'] );
	}

	/**
	 * Fetches a user ID by API key.
	 *
	 * @access private
	 * @since  1.0.0
	 * @param  string $api_key The API key attached to a user.
	 * @return mixed           A user ID on success, or false on failure.
	 */
	private static function find_user_id_by_key( $api_key ) {

		$user_args = array(
			'meta_query' => array(
				array(
					'key'   => 'rest_api_key',
					'value' => $api_key,
				),
			),
			'number'     => 1,
			'fields'     => array( 'ID' ),
		);

		$user = \get_users( $user_args );

		if ( empty( $user ) ) {
			return false;
		}

		if ( ! is_array( $user ) ) {
			return false;
		}

		if ( sizeof( $user ) > 1 ) {
			return false;
		}

		return $user[0]->ID;
	}

	/**
	 * Sets the response headers.
	 *
	 * @access private
	 * @since  1.0.0
	 * @param  string    $value    Response header value.
	 * @param  string    $key      Response header key.
	 */
	private static function set_response_headers( $value, $key = 'X-KEY-AUTH' ) {
		header( sprintf( '%s: %s', strtoupper( $key ), $value ) );
	}

	/**
	 * Checks if the timestamp is within a defined interval.
	 *
	 * @access private
	 * @since  1.0.0
	 * @return bool True if the timestamp is valid, false otherwise.
	 */
	private static function valid_timestamp() {
		$timestamp = intval( $_SERVER['HTTP_X_API_TIMESTAMP'] );
		$interval  = \apply_filters( 'rest_key_auth_timestamp_interval', 5 * MINUTE_IN_SECONDS );
		return abs( time() - $timestamp ) <= $interval;
	}

	/**
	 * Generate a hash signature.
	 *
	 * @access private
	 * @since  1.0.0
	 * @param  array  $args   The arguments used for generating the signature.
	 *                        They should be, in order:
	 *                        'api_key', 'ip', 'request_method', 'request_post', 'request_uri', 'timestamp'
	 *                        Timestamp should be the timestamp passed in the request.
	 * @param  string $secret The API secret we are using to generate the hash.
	 * @return string         Return hash of the secret.
	 */
	private static function generate_signature( $args, $secret ) {
		return hash( \apply_filters( 'rest_key_auth_signature_algo', 'sha256' ), json_encode( $args ) . $secret );
	}
}

<?php

/**
 * The dashboard-specific functionality of the plugin.
 *
 * @link       http://log.pt/
 * @since      1.0.0
 *
 * @package    RestKeyAuth
 * @subpackage RestKeyAuth/lib
 */

namespace logoscon\RestKeyAuth;

/**
 * The dashboard-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the dashboard-specific stylesheet and JavaScript.
 *
 * @package    RestKeyAuth
 * @subpackage RestKeyAuth/lib
 * @author     log.OSCON, Lda. <engenharia@log.pt>
 */
class Admin {

	/**
	 * The plugin's instance.
	 *
	 * @since  1.0.0
	 * @access private
	 * @var    Plugin $plugin This plugin's instance.
	 */
	private $plugin;

	/**
	 * Initialize the class and set its properties.
	 *
	 * @since 1.0.0
	 *
	 * @param Plugin $plugin This plugin's instance.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * The primary handler for user authentication.
	 *
	 * @since     0.1.0
	 * @param     mixed    $user    User ID if one has been determined, false otherwise.
	 * @return    mixed             A user on success, or false on failure.
	 */
	public function auth_handler( $user ) {

		// Don't authenticate twice
		if ( ! empty( $user ) ) {
			return $user;
		}

		// Check for request headers
		if ( ! $this->check_request_headers() ) {
			return $user;
		}

		// Fetch user ID
		$user_id = $this->find_user_id_by_key( $_SERVER[ 'HTTP_X_API_KEY' ] );

		if ( ! $user_id ) {
			$this->set_response_headers( 'FAIL api key' );
			return false;
		}

		// Check timestamp
		if ( ! $this->valid_timestamp() ) {
			$this->set_response_headers( 'FAIL timestamp' );
			return false;
		}

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key'        => $_SERVER[ 'HTTP_X_API_KEY' ],
			'ip'             => $_SERVER[ 'REMOTE_ADDR' ],
			'request_method' => $_SERVER[ 'REQUEST_METHOD' ],
			'request_post'   => $_POST,
			'request_uri'    => $_SERVER[ 'REQUEST_URI' ],
			'timestamp'      => $_SERVER[ 'HTTP_X_API_TIMESTAMP' ],
		);

		$user_secret   = \get_user_meta( $user_id, 'rest_api_secret', true );
		$signature_gen = self::generate_signature( $signature_args, $user_secret );
		$signature     = $_SERVER[ 'HTTP_X_API_SIGNATURE' ];

		if ( $signature_gen !== $signature ) {
			$this->set_response_headers( 'FAIL signature' );
			return false;
		}

		// Set headers
		$this->set_response_headers( 'OK ' . $user_id );

		return $user_id;
	}

	/**
	 * Checks for the presence of required request headers.
	 *
	 * @access    private
	 * @since     1.0.0
	 * @return    bool    True if the request headers are present, false otherwise.
	 */
	private function check_request_headers() {
		return
			isset( $_SERVER[ 'HTTP_X_API_KEY' ] ) &&
			isset( $_SERVER[ 'HTTP_X_API_TIMESTAMP' ] ) &&
			isset( $_SERVER[ 'HTTP_X_API_SIGNATURE' ] );
	}

	/**
	 * Fetches a user ID by API key.
	 *
	 * @access    private
	 * @since     0.1.0
	 * @param     string    $api_key    The API key attached to a user.
	 * @return    mixed                 A user ID on success, or false on failure.
	 */
	private function find_user_id_by_key( $api_key ) {

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
	 * @access    private
	 * @since     1.0.0
	 * @param     string    $value    Response header value.
	 * @param     string    $key      Response header key.
	 */
	private function set_response_headers( $value, $key = 'X-KEY-AUTH' ) {
		header( sprintf( '%s: %s', strtoupper( $key ), $value ) );
	}

	/**
	 * Checks if the timestamp is within a defined interval.
	 *
	 * @access    private
	 * @since     1.0.0
	 * @return    bool    True if the timestamp is valid, false otherwise.
	 */
	private function valid_timestamp() {

		$timestamp = intval( $_SERVER[ 'HTTP_X_API_TIMESTAMP' ] );
		$interval  = \apply_filters( 'rest_key_auth_timestamp_interval', 5 * MINUTE_IN_SECONDS );

		return abs( time() - $timestamp ) <= $interval;
	}

	/**
	 * Generate a hash signature.
	 *
	 * @access    private
	 * @since     0.1.0
	 * @param     array     $args      The arguments used for generating the signature. They should be, in order:
	 *                                 'api_key', 'timestamp', 'request_method', and 'request_uri'.
	 *                                 Timestamp should be the timestamp passed in the request.
	 * @param     string    $secret    The API secret we are using to generate the hash.
	 * @return    string               Return hash of the secret.
	 */
	private function generate_signature( $args, $secret ) {
		return hash( \apply_filters( 'rest_key_auth_signature_algo', 'sha256' ), json_encode( $args ) . $secret );
	}

	/**
	 * Add entries to regenerate the API secret key and secret in the user admin panel.
	 *
	 * @since    1.0.0
	 * @param    \WP_User    $user    The user being edited.
	 */
	public function user_profile( $user ) {

		$api_key    = \get_user_meta( $user->ID, 'rest_api_key', true );
		$api_secret = \get_user_meta( $user->ID, 'rest_api_secret', true );

		include 'Admin/UserProfile.php';

	}

	/**
	 * Regenerates the user's API key and secret.
	 *
	 * @since    1.0.0
	 * @param    int    $user_id    User ID for the user being updated.
	 */
	public function user_profile_update( $user_id ) {

		// Regenerate API key
		if ( isset( $_POST[ 'reset_rest_api_key' ] ) && $_POST[ 'reset_rest_api_key' ] ) {
			\update_user_meta( $user_id, 'rest_api_key', \wp_generate_password( 32, false ) );
		}

		// Regenerate API secret
		if ( isset( $_POST[ 'reset_rest_api_secret' ] ) && $_POST[ 'reset_rest_api_secret' ] ) {
			\update_user_meta( $user_id, 'rest_api_secret', \wp_generate_password( 32, false ) );
		}

	}

}

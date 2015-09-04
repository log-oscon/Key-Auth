<?php
/**
 * WP REST API Key Authentication
 *
 * API/Secret Key Authentication handler for the WP REST API.
 *
 * @link              http://log.pt/
 * @since             1.0.0
 * @package           WpRestKeyAuth
 *
 * @wordpress-plugin
 * Plugin Name:       WP REST API Key Authentication
 * Plugin URI:        https://github.com/log-oscon/key-auth
 * Description:       API/Secret Key Authentication handler for the WP REST API.
 * Version:           0.2.0
 * Author:            log.OSCON, Lda.
 * Author URI:        http://log.pt/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       key-auth
 * Domain Path:       /languages
 */

/**
 * Checks the HTTP request and authenticates a user using an API key and shared secret.
 *
 * @since    0.1.0
 * @param    mixed    $user    The current user passed in the filter.
 */

class WP_REST_Key_Auth {

	/**
	 * The primary handler for user authentication.
	 *
	 * @since     0.1.0
	 * @param     mixed    $user    The current user (or bool) passing through the filter.
	 * @return    mixed             A user on success, or false on failure.
	 */
	public static function auth_handler( $user ) {

		// Don't authenticate twice
		if ( ! empty( $user ) ) {
			return $user;
		}

		// Check for request headers
		if ( ! self::check_request_headers() ) {
			return $user;
		}

		// Fetch user ID
		$user_id = self::find_user_id_by_key( $_SERVER['HTTP_X_API_KEY'] );

		if ( ! $user_id ) {
			self::set_response_headers( 'FAIL api key' );
			return false;
		}

		// Check timestamp
		if ( ! self::valid_timestamp() ) {
			self::set_response_headers( 'FAIL timestamp' );
			return false;
		}

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key'        => $_SERVER['HTTP_X_API_KEY'],
			'ip'             => $_SERVER['REMOTE_ADDR'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_post'   => $_POST,
			'request_uri'    => $_SERVER['REQUEST_URI'],
			'timestamp'      => $_SERVER['HTTP_X_API_TIMESTAMP'],
		);

		$user_secret   = get_user_meta( $user_id, 'json_shared_secret', true );
		$signature_gen = self::generate_signature( $signature_args, $user_secret );
		$signature     = $_SERVER['HTTP_X_API_SIGNATURE'];

		if ( $signature_gen !== $signature ) {
			self::set_response_headers( 'FAIL signature' );
			return false;
		}

		// Set headers
		self::set_response_headers( 'OK ' . $user_id );

		return $user_id;
	}

	/**
	 * Checks for the presence of required request headers.
	 *
	 * @since     0.2.0
	 * @return    bool    True if the request headers are present, false otherwise.
	 */
	public static function check_request_headers() {
		return isset( $_SERVER['HTTP_X_API_KEY'] ) &&
				isset( $_SERVER['HTTP_X_API_TIMESTAMP'] ) &&
				isset( $_SERVER['HTTP_X_API_SIGNATURE'] );
	}

	/**
	 * Sets the response headers.
	 *
	 * @since    0.2.0
	 * @param    string    $value
	 * @param    string    $key
	 */
	public static function set_response_headers( $value, $key = 'X-KEY-AUTH' ) {
		header( sprintf( '%s: %s', strtoupper( $key ), $value ) );
	}

	/**
	 * Checks if the timestamp is within a defined interval.
	 *
	 * @since     0.2.0
	 * @return    bool    True if the timestamp is valid, false otherwise.
	 */
	public static function valid_timestamp() {

		$timestamp = intval( $_SERVER['HTTP_X_API_TIMESTAMP'] );
		$interval  = apply_filters( 'rest_key_auth_timestamp_interval', 5 * MINUTE_IN_SECONDS );

		return abs( time() - $timestamp ) <= $interval;
	}

	/**
	 * Generate a hash signature.
	 *
	 * @since     0.1.0
	 * @param     array     $args      The arguments used for generating the signature. They should be, in order:
	 *                                 'api_key', 'timestamp', 'request_method', and 'request_uri'.
	 *                                 Timestamp should be the timestamp passed in the request.
	 * @param     string    $secret    The shared secret we are using to generate the hash.
	 * @return    string               Return hash of the secret.
	 */
	public static function generate_signature( $args, $secret ) {

		// Name of selected hashing algorithm
		$algo = apply_filters( 'rest_key_auth_signature_algo', 'sha256' );

		return hash( $algo, json_encode( $args ) . $secret );
	}

	/**
	 * Fetches a user ID by API key.
	 *
	 * @since     0.1.0
	 * @param     string    $api_key    The API key attached to a user.
	 * @return    mixed                 A user ID on success, or false on failure.
	 */
	public static function find_user_id_by_key( $api_key ) {

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

		if ( empty( $user ) || ! is_array( $user ) ) {
			return false;
		}

		return $user[0]->ID;
	}

	/**
	 * Add entries to regenerate the API secret key and shared secret in the user admin panel.
	 *
	 * @since    0.2.0
	 * @param    WP_User    $user    User being edited.
	 */
	public static function user_profile( $user ) {

		$json_api_key       = get_user_meta( $user->ID, 'json_api_key', true );
		$json_shared_secret = get_user_meta( $user->ID, 'json_shared_secret', true );

		?>
		<table class="form-table">
			<tbody>
				<tr>
					<th scope="row"><?php _e( 'REST API Key', 'key-auth' ); ?></th>
					<td>
						<?php

							if ( ! empty( $json_api_key ) ) {
								printf(
									'<input type="text" name="json_api_key" id="json_api_key" value="%s" disabled="disabled" class="regular-text">',
									$json_api_key
								);
							}

							printf(
								'<p><label><input type="checkbox" id="reset_json_api_key" name="reset_json_api_key" value="1">%s</label></p>',
								empty( $json_api_key ) ? __( 'Generate Key', 'key-auth' ) : __( 'Reset Key', 'key-auth' )
							);

						?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php _e( 'REST API Shared Secret', 'key-auth' ); ?></th>
					<td>
						<?php

							if ( ! empty( $json_shared_secret ) ) {
								printf(
									'<input type="text" name="json_shared_secret" id="json_shared_secret" value="%s" disabled="disabled" class="regular-text">',
									$json_shared_secret
								);
							}

							printf(
								'<p><label><input type="checkbox" id="reset_json_shared_secret" name="reset_json_shared_secret" value="1">%s</label></p>',
								empty(  $json_shared_secret ) ? __( 'Generate Shared Secret', 'key-auth' ) : __( 'Reset Shared Secret', 'key-auth' )
							);

						?>
					</td>
				</tr>
			</tbody>
		</table>

		<?php
	}

	/**
	 * Regenerates the user's API key and shared secret.
	 *
	 * @since    0.2.0
	 * @param    int    $user_id    User ID for the user being updated.
	 */
	public static function user_profile_update( $user_id ) {

		// Regenerate API key
		$regenerate_api_key = isset( $_POST['reset_json_api_key'] ) && $_POST['reset_json_api_key'];
		if ( $regenerate_api_key ) {
			$api_key = wp_generate_password( 32, false );
			update_user_meta( $user_id, 'json_api_key', $api_key );
		}

		// Regenerate shared secret
		$regenerate_shared_secret = isset( $_POST['reset_json_shared_secret'] ) && $_POST['reset_json_shared_secret'];

		if ( $regenerate_shared_secret ) {
			$shared_secret = wp_generate_password( 32, false );
			update_user_meta( $user_id, 'json_shared_secret', $shared_secret );
		}
	}

}

add_filter( 'determine_current_user',   array( 'WP_REST_Key_Auth', 'auth_handler' ), 20 );
add_action( 'show_user_profile',        array( 'WP_REST_Key_Auth', 'user_profile' ), 90 );
add_action( 'edit_user_profile',        array( 'WP_REST_Key_Auth', 'user_profile' ), 90 );
add_action( 'personal_options_update',  array( 'WP_REST_Key_Auth', 'user_profile_update' ) );
add_action( 'edit_user_profile_update', array( 'WP_REST_Key_Auth', 'user_profile_update' ) );

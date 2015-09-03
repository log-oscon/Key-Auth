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

class WP_REST_Key_Auth {

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

		$user_id = self::findUserIdByKey( $_SERVER['HTTP_X_API_KEY'] );

		if ( ! $user_id ) {
			return false;
		}

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key'        => $_SERVER['HTTP_X_API_KEY'],
			'timestamp'      => $_SERVER['HTTP_X_API_TIMESTAMP'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_uri'    => $_SERVER['REQUEST_URI'],
		);

		$user_secret   = get_user_meta( $user_id, 'json_shared_secret', true );
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
	 *                                 Timestamp should be the timestamp passed in the request.
	 * @param     string    $secret    The shared secret we are using to generate the hash.
	 * @return    string               Return md5 hash of the secret.
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
	public static function userProfile( $user ) {

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
	public static function userProfileUpdate( $user_id ) {

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

add_filter( 'determine_current_user',   array( 'WP_REST_Key_Auth', 'authHandler' ), 20 );
add_action( 'show_user_profile',        array( 'WP_REST_Key_Auth', 'userProfile' ), 90 );
add_action( 'edit_user_profile',        array( 'WP_REST_Key_Auth', 'userProfile' ), 90 );
add_action( 'personal_options_update',  array( 'WP_REST_Key_Auth', 'userProfileUpdate' ) );
add_action( 'edit_user_profile_update', array( 'WP_REST_Key_Auth', 'userProfileUpdate' ) );

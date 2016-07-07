<?php
/**
 * The dashboard-specific functionality of the plugin.
 *
 * @link       http://log.pt/
 * @since      1.0.0
 *
 * @package    RESTKeyAuth
 * @subpackage RESTKeyAuth/lib
 */

namespace logoscon\RESTKeyAuth;

/**
 * The dashboard-specific functionality of the plugin.
 *
 * @package    RESTKeyAuth
 * @subpackage RESTKeyAuth/lib
 * @author     log.OSCON, Lda. <engenharia@log.pt>
 */
class Admin {

	/**
	 * The plugin's instance.
	 *
	 * @since  1.0.0
	 * @access private
	 * @var    Plugin
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
	 * Add entries to regenerate the API secret key and secret in the user admin panel.
	 *
	 * @since 1.0.0
	 * @param \WP_User $user The user being edited.
	 */
	public function user_profile( $user ) {
		$api_key    = \get_user_meta( $user->ID, 'rest_api_key', true );
		$api_secret = \get_user_meta( $user->ID, 'rest_api_secret', true );
		include 'Admin/UserProfile.php';
	}

	/**
	 * Regenerates the user's API key and secret.
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID for the user being updated.
	 */
	public function user_profile_update( $user_id ) {

		// Regenerate API key
		if ( isset( $_POST['reset_rest_api_key'] ) && $_POST['reset_rest_api_key'] ) {
			\update_user_meta( $user_id, 'rest_api_key', \wp_generate_password( 32, false ) );
		}

		// Regenerate API secret
		if ( isset( $_POST['reset_rest_api_secret'] ) && $_POST['reset_rest_api_secret'] ) {
			\update_user_meta( $user_id, 'rest_api_secret', \wp_generate_password( 32, false ) );
		}

	}
}

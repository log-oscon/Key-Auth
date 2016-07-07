<?php

/**
 * WP REST API Key Authentication
 *
 * API/Secret Key Authentication handler for the WP REST API.
 *
 * @link              http://log.pt/
 * @since             1.0.0
 * @package           RESTKeyAuth
 *
 * @wordpress-plugin
 * Plugin Name:       WP REST API Key Authentication
 * Plugin URI:        https://github.com/log-oscon/key-auth/
 * Description:       API/Secret Key Authentication handler for the WP REST API.
 * Version:           1.1.0
 * Author:            log.OSCON, Lda.
 * Author URI:        http://log.pt/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       key-auth
 * Domain Path:       /languages
 */

if ( file_exists( dirname( __FILE__ ) . '/vendor/autoload.php' ) ) {
	require_once dirname( __FILE__ ) . '/vendor/autoload.php';
}

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Begins execution of the plugin.
 *
 * @since    1.0.0
 */
\add_action( 'plugins_loaded', function () {
    $plugin = new \logoscon\RESTKeyAuth\Plugin();
    $plugin->run();
} );

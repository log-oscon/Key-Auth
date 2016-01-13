<?php
/**
 * Provide a admin area view for the plugin
 *
 * This file is used to markup the admin-facing aspects of the plugin.
 *
 * @link       http://log.pt/
 * @since      1.0.0
 *
 * @package    RestKeyAuth
 * @subpackage RestKeyAuth/lib/Admin
 */
?>
<table class="form-table">
	<tbody>
		<tr>
			<th scope="row">
				<?php _e( 'REST API Key', 'key-auth' ); ?>
			</th>
			<td>
				<?php
					if ( ! empty( $api_key ) ) {
						printf(
							'<input type="text" name="rest_api_key" id="rest_api_key" value="%s" disabled="disabled" class="regular-text">',
							$api_key
						);
					}

					printf(
						'<p><label><input type="checkbox" id="reset_rest_api_key" name="reset_rest_api_key" value="1">%s</label></p>',
						empty( $api_key ) ? __( 'Generate Key', 'key-auth' ) : __( 'Reset Key', 'key-auth' )
					);
				?>
			</td>
		</tr>
		<tr>
			<th scope="row">
				<?php _e( 'REST API Shared Secret', 'key-auth' ); ?>
			</th>
			<td>
				<?php
					if ( ! empty( $api_secret ) ) {
						printf(
							'<input type="text" name="rest_api_secret" id="rest_api_secret" value="%s" disabled="disabled" class="regular-text">',
							$api_secret
						);
					}

					printf(
						'<p><label><input type="checkbox" id="reset_rest_api_secret" name="reset_rest_api_secret" value="1">%s</label></p>',
						empty(  $api_secret ) ? __( 'Generate Shared Secret', 'key-auth' ) : __( 'Reset Shared Secret', 'key-auth' )
					);
				?>
			</td>
		</tr>
	</tbody>
</table>

<?php
/**
 * Plugin Name: JSON Basic Authentication
 * Description: Basic Authentication handler for the JSON API, used for development and debugging purposes
 * Author: WordPress API Team
 * Author URI: https://github.com/WP-API
 * Version: 0.1
 * Plugin URI: https://github.com/WP-API/Basic-Auth
 */
 

function json_basic_auth_handler( $request ) {
	global $wp_json_basic_auth_error;

	$wp_json_basic_auth_error = null;
 
	// Check that we're trying to authenticate
	if ( !isset( $_SERVER['PHP_AUTH_USER'] ) ) {
		return $request;
	}

	$username = $_SERVER['PHP_AUTH_USER'];
	$is_email = strpos($username, '@');
	if($is_email){
		$ud = get_user_by_email( $username );
		$username = $ud->user_login;
	}
	$password = $_SERVER['PHP_AUTH_PW'];
	$user = wp_authenticate($username, $password ); 

		if( $user ) {
		    wp_set_current_user( $user->ID, $user->user_login );
		    wp_set_auth_cookie( $user->ID );
		    do_action( 'wp_login', $user->user_login );
		}


	/**
	 * In multi-site, wp_authenticate_spam_check filter is run on authentication. This filter calls
	 * get_currentuserinfo which in turn calls the determine_current_user filter. This leads to infinite
	 * recursion and a stack overflow unless the current function is removed from the determine_current_user
	 * filter during authentication.
	 */
  
	if ( is_wp_error( $user ) ) {
		$wp_json_basic_auth_error = $user;
		return null;
	}

	$wp_json_basic_auth_error = true;

	return null;
}
add_filter( 'rest_pre_dispatch', 'json_basic_auth_handler', 80 );

function json_basic_auth_error( $error ) {
	// Passthrough other errors
	if ( ! empty( $error ) ) {
		return $error;
	}

	global $wp_json_basic_auth_error;

	return $wp_json_basic_auth_error;
}
add_filter( 'json_basic_auth_error', 'json_basic_auth_error' );

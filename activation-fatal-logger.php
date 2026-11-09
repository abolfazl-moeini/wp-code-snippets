<?php
/**
 * Plugin Name: Activation Fatal Error Logger (MU)
 * Description: Captures PHP fatal errors thrown while a plugin is being activated and logs them safely.
 * Version:     1.2.0
 *
 * Install: wp-content/mu-plugins/activation-fatal-logger.php
 *
 * How detection works (verified against WordPress core):
 * - activate_plugin() (admin single/bulk, AJAX "activate-plugin", REST, WP-CLI) and resume_plugin()
 *   call plugin_sandbox_scrape(), which defines WP_SANDBOX_SCRAPING right before include_once-ing the
 *   plugin. That constant is therefore the one reliable "a plugin is being activated" signal, and it
 *   can only be set by core code (not by a crafted URL).
 * - The plugins.php?action=error_scrape iframe re-includes the same broken plugin, so it is skipped
 *   to avoid logging the same fatal twice.
 *
 * Optional constant: define( 'AFL_LOG_FILE', '/path/outside/webroot/afl.log.php' ); (keep the .php
 * extension so the "<?php exit; ?>" guard line stays effective if the file is ever web-accessible).
 */

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'AFL_OPTION' ) ) {
	define( 'AFL_OPTION', 'afl_activation_fatal_errors' );
}

/**
 * Plugin currently inside activate_plugin()'s activation hooks (set after the sandbox include succeeded).
 * A fatal at plugin top level happens BEFORE this is set, so the plugin is then inferred from the error path.
 */
$GLOBALS['afl_current_activating_plugin'] = null;

add_action(
	'activate_plugin',
	static function ( $plugin ) {
		$GLOBALS['afl_current_activating_plugin'] = is_string( $plugin ) ? $plugin : null;
	},
	0
);

add_action(
	'activated_plugin',
	static function () {
		$GLOBALS['afl_current_activating_plugin'] = null;
	},
	9999
);

/**
 * Collapse whitespace/control characters (prevents log injection, keeps one entry per line) and truncate.
 */
function afl_one_line( $value, $max = 1000 ) {
	$clean = preg_replace( '/[\x00-\x20\x7F]+/', ' ', (string) $value );
	$clean = trim( null === $clean ? (string) $value : $clean );
	return strlen( $clean ) > $max ? substr( $clean, 0, $max ) . '...' : $clean;
}

/**
 * Current request action; honours the bottom bulk dropdown (action=-1 & action2=...).
 */
function afl_request_action() {
	foreach ( array( 'action', 'action2' ) as $key ) {
		if ( isset( $_REQUEST[ $key ] ) && is_string( $_REQUEST[ $key ] ) && '' !== $_REQUEST[ $key ] && '-1' !== $_REQUEST[ $key ] ) {
			return sanitize_key( wp_unslash( $_REQUEST[ $key ] ) );
		}
	}
	return '';
}

/**
 * The error_scrape iframe re-runs the same fatal as the activation request that was already logged.
 */
function afl_is_error_scrape_request() {
	$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( (string) $_SERVER['SCRIPT_NAME'] ) : '';
	return 'plugins.php' === $script && 'error_scrape' === afl_request_action();
}

function afl_is_activation_request() {
	if ( afl_is_error_scrape_request() ) {
		return false;
	}
	if ( ! empty( $GLOBALS['afl_current_activating_plugin'] ) ) {
		return true;
	}
	return defined( 'WP_SANDBOX_SCRAPING' ) && WP_SANDBOX_SCRAPING;
}

/**
 * Plugin the fatal most likely comes from: exact hook value first, then the error file's plugin folder.
 */
function afl_get_culprit_plugin( array $error ) {
	if ( ! empty( $GLOBALS['afl_current_activating_plugin'] ) ) {
		return (string) $GLOBALS['afl_current_activating_plugin'];
	}

	if ( ! empty( $error['file'] ) && defined( 'WP_PLUGIN_DIR' ) && function_exists( 'wp_normalize_path' ) ) {
		$file       = wp_normalize_path( $error['file'] );
		$plugin_dir = rtrim( wp_normalize_path( WP_PLUGIN_DIR ), '/' ) . '/';
		if ( 0 === strpos( $file, $plugin_dir ) ) {
			$parts = explode( '/', substr( $file, strlen( $plugin_dir ) ) );
			return (string) $parts[0];
		}
	}

	return '';
}

/**
 * Plugin(s) the request asked to activate (best effort, may list several for bulk/CLI).
 */
function afl_get_requested_target() {
	if ( isset( $_REQUEST['plugin'] ) && is_string( $_REQUEST['plugin'] ) && '' !== $_REQUEST['plugin'] ) {
		return (string) wp_unslash( $_REQUEST['plugin'] );
	}

	// REST: /wp-json/wp/v2/plugins/<plugin> or ?rest_route=/wp/v2/plugins/<plugin>
	$route = isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] )
		? wp_unslash( $_GET['rest_route'] )
		: ( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '' );
	if ( preg_match( '#wp/v2/plugins/([^?&\#]+)#', (string) $route, $m ) ) {
		return rtrim( urldecode( $m[1] ), '/' );
	}

	// Bulk activation: the failing plugin cannot be told apart from the request alone.
	if ( isset( $_REQUEST['checked'] ) && is_array( $_REQUEST['checked'] ) ) {
		$list = array_filter( array_map( 'strval', array_filter( (array) wp_unslash( $_REQUEST['checked'] ), 'is_scalar' ) ) );
		return 'bulk: ' . implode( ', ', $list );
	}

	// WP-CLI: wp plugin activate <slug> [<slug> ...]
	if ( defined( 'WP_CLI' ) && WP_CLI && ! empty( $GLOBALS['argv'] ) && is_array( $GLOBALS['argv'] ) ) {
		$idx = array_search( 'activate', $GLOBALS['argv'], true );
		if ( false !== $idx ) {
			$slugs = array();
			foreach ( array_slice( $GLOBALS['argv'], $idx + 1 ) as $arg ) {
				if ( is_string( $arg ) && '' !== $arg && '-' !== $arg[0] ) {
					$slugs[] = $arg;
				}
			}
			if ( $slugs ) {
				return 'cli: ' . implode( ', ', $slugs );
			}
		}
	}

	return '';
}

function afl_write_log_line( $line ) {
	$default = ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content' ) . '/activation-fatal-errors.log.php';
	$file    = defined( 'AFL_LOG_FILE' ) ? AFL_LOG_FILE : $default;

	// PHP guard line: if the file is ever requested over HTTP it just exits. Start over when it exceeds 1 MB.
	if ( ! file_exists( $file ) || @filesize( $file ) > 1048576 ) {
		if ( false === @file_put_contents( $file, "<?php exit; ?>\n", LOCK_EX ) ) {
			return;
		}
		@chmod( $file, 0640 );
	}
	@file_put_contents( $file, $line, FILE_APPEND | LOCK_EX );
}

function afl_store_entry( array $entry ) {
	if ( ! function_exists( 'update_option' ) || ! function_exists( 'get_option' ) ) {
		return;
	}

	$multi  = function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'update_site_option' );
	$stored = $multi ? get_site_option( AFL_OPTION, array() ) : get_option( AFL_OPTION, array() );
	$stored = is_array( $stored ) ? $stored : array();

	$stored[] = $entry;
	$stored   = array_slice( $stored, -20 );

	if ( $multi ) {
		update_site_option( AFL_OPTION, $stored );
	} else {
		update_option( AFL_OPTION, $stored, false ); // autoload = false: never load this on every request.
	}
}

function afl_get_entries() {
	$stored = is_multisite() ? get_site_option( AFL_OPTION, array() ) : get_option( AFL_OPTION, array() );
	return is_array( $stored ) ? $stored : array();
}

function afl_shutdown_handler() {
	try {
		$error = error_get_last();
		if ( ! $error ) {
			return;
		}

		// Same set WordPress core's fatal error handler treats as fatal.
		$fatal_types = array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR );
		if ( ! in_array( $error['type'], $fatal_types, true ) ) {
			return;
		}

		if ( ! function_exists( 'sanitize_key' ) || ! function_exists( 'wp_unslash' ) || ! afl_is_activation_request() ) {
			return;
		}

		$target  = afl_get_requested_target();
		$culprit = afl_get_culprit_plugin( $error );
		$plugin  = '' !== $culprit ? $culprit : ( '' !== $target ? $target : 'unknown' );

		// Never log nonces; strip control characters from everything that came from the request.
		$raw_url = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$url     = function_exists( 'remove_query_arg' ) ? remove_query_arg( array( '_wpnonce', '_error_nonce', '_ajax_nonce' ), $raw_url ) : $raw_url;

		$entry = array(
			'time'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'plugin'  => afl_one_line( $plugin, 300 ),
			'target'  => afl_one_line( $target, 500 ),
			'type'    => (int) $error['type'],
			'message' => afl_one_line( $error['message'], 2000 ),
			'file'    => afl_one_line( $error['file'], 500 ),
			'line'    => (int) $error['line'],
			'url'     => afl_one_line( $url, 500 ),
			'php'     => PHP_VERSION,
		);

		// 1) Guarded log file (works even if the database is unavailable).
		afl_write_log_line(
			sprintf(
				"[%s] plugin=%s | target=%s | type=%d | %s in %s:%d | url=%s | php=%s\n",
				$entry['time'],
				$entry['plugin'],
				$entry['target'],
				$entry['type'],
				$entry['message'],
				$entry['file'],
				$entry['line'],
				$entry['url'],
				$entry['php']
			)
		);

		// 2) Last 20 entries for the admin notice.
		afl_store_entry( $entry );
	} catch ( \Throwable $e ) {
		// Never raise a second error from a shutdown handler.
		return;
	}
}
register_shutdown_function( 'afl_shutdown_handler' );

/**
 * Capability needed to see/clear entries (network-wide store on Multisite).
 */
function afl_viewer_cap() {
	return is_multisite() ? 'manage_network_plugins' : 'activate_plugins';
}

/**
 * Clear the stored entries on admin_init, then redirect so the nonce URL does not stay in the address bar.
 */
add_action(
	'admin_init',
	static function () {
		if ( empty( $_GET['afl_clear'] ) || ! current_user_can( afl_viewer_cap() ) ) {
			return;
		}
		check_admin_referer( 'afl_clear' );
		if ( is_multisite() ) {
			delete_site_option( AFL_OPTION );
		} else {
			delete_option( AFL_OPTION );
		}
		wp_safe_redirect( remove_query_arg( array( 'afl_clear', '_wpnonce' ) ) );
		exit;
	}
);

function afl_render_admin_notice() {
	if ( ! current_user_can( afl_viewer_cap() ) ) {
		return;
	}

	$errors = afl_get_entries();
	if ( empty( $errors ) ) {
		return;
	}

	$last      = end( $errors );
	$clear_url = wp_nonce_url( add_query_arg( 'afl_clear', '1' ), 'afl_clear' );

	printf(
		'<div class="notice notice-error"><p><strong>Plugin activation fatal error</strong> (%s, %s)<br><code>%s</code><br>in <code>%s:%d</code> &mdash; <a href="%s">Dismiss</a></p></div>',
		esc_html( isset( $last['plugin'] ) ? $last['plugin'] : 'unknown' ),
		esc_html( isset( $last['time'] ) ? $last['time'] : '' ),
		esc_html( isset( $last['message'] ) ? $last['message'] : '' ),
		esc_html( isset( $last['file'] ) ? $last['file'] : '' ),
		isset( $last['line'] ) ? (int) $last['line'] : 0,
		esc_url( $clear_url )
	);
}
add_action( 'admin_notices', 'afl_render_admin_notice' );
add_action( 'network_admin_notices', 'afl_render_admin_notice' );

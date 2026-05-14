<?php
/**
 * Greenskeeper — Site Activity Log
 *
 * Captures and stores key site events: authentication, user management,
 * and site configuration changes. Designed as a lightweight maintenance
 * audit trail — not a full security scanner.
 *
 * GDPR compliance:
 *   - IP addresses are anonymised by default (last octet zeroed for IPv4,
 *     last 80 bits zeroed for IPv6) unless the admin explicitly opts in
 *     to storing full IPs.
 *   - A configurable retention period (default 90 days) automatically
 *     purges old records via a daily wp-cron event.
 *   - A data export tool lets admins download all stored activity data
 *     in CSV format to satisfy Subject Access Requests.
 *   - All logged data can be bulk-deleted from the Activity Log admin page.
 *
 * @package Greenskeeper
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ── Event category constants ───────────────────────────────────────────────────
define( 'WPMM_ACTIVITY_AUTH',    'authentication' );
define( 'WPMM_ACTIVITY_USER',    'user_management' );
define( 'WPMM_ACTIVITY_SITE',    'site_change' );
define( 'WPMM_ACTIVITY_CONTENT', 'content' );  // reserved for Pro

// ── Core logger function ───────────────────────────────────────────────────────

/**
 * Insert one activity log entry.
 *
 * @param string $event      Machine-readable event identifier (e.g. 'user_login').
 * @param string $category   One of the WPMM_ACTIVITY_* constants.
 * @param string $summary    Human-readable one-line description shown in the UI.
 * @param array  $context    Optional key-value pairs stored as JSON for detail view.
 * @param int    $user_id    WordPress user ID. 0 = unauthenticated / system.
 */
function wpmm_log_activity( $event, $category, $summary, $context = [], $user_id = 0 ) {
    global $wpdb;

    $s = wpmm_get_settings();

    // Respect the activity log enabled toggle.
    if ( empty( $s['activity_log_enabled'] ) ) {
        return;
    }

    // Resolve user ID from current user if not provided.
    if ( ! $user_id ) {
        $user_id = get_current_user_id();
    }

    // Resolve user display name and login.
    $user_login = '';
    $user_name  = '';
    if ( $user_id ) {
        $u = get_user_by( 'id', $user_id );
        if ( $u ) {
            $user_login = $u->user_login;
            $user_name  = $u->display_name ?: $u->user_login;
        }
    }

    // ── IP address handling ────────────────────────────────────────────────────
    // We collect the raw IP for processing, then immediately anonymise it
    // unless the site admin has opted in to full IP storage.
    $raw_ip = '';
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $raw_ip = sanitize_text_field( wp_unslash( explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] )[0] ) );
    } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
        $raw_ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
    }

    $store_full_ip = ! empty( $s['activity_log_full_ip'] );
    $ip            = $store_full_ip ? $raw_ip : wpmm_anonymise_ip( $raw_ip );

    // ── Context sanitisation ───────────────────────────────────────────────────
    // Never store passwords, secrets, or capability keys in context.
    $safe_keys = [ 'plugin', 'theme', 'version', 'old_version', 'new_version',
                   'role', 'old_role', 'new_role', 'option_name', 'post_type',
                   'object_id', 'network', 'site_id', 'reason' ];
    $clean_ctx = [];
    foreach ( $context as $k => $v ) {
        if ( in_array( $k, $safe_keys, true ) || strpos( $k, 'wpmm_' ) === 0 ) {
            $clean_ctx[ sanitize_key( $k ) ] = is_scalar( $v )
                ? sanitize_text_field( (string) $v )
                : wp_json_encode( $v );
        }
    }

    $activity_table = esc_sql( $wpdb->prefix . 'wpmm_activity_log' );

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
    $wpdb->insert(
        $activity_table,
        [
            'event'      => sanitize_key( $event ),
            'category'   => sanitize_key( $category ),
            'summary'    => sanitize_text_field( $summary ),
            'context'    => wp_json_encode( $clean_ctx ),
            'user_id'    => absint( $user_id ),
            'user_login' => sanitize_user( $user_login ),
            'user_name'  => sanitize_text_field( $user_name ),
            'ip_address' => $ip,
            'logged_at'  => current_time( 'mysql' ),
        ],
        [ '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s' ]
    );
}

/**
 * Anonymise an IP address.
 *
 * IPv4: zero the last octet  (192.168.1.100 → 192.168.1.0)
 * IPv6: zero the last 80 bits (keeps the first 48 bits for geo context)
 *
 * This matches the approach used by Google Analytics and recommended
 * by GDPR guidance from the European Data Protection Board.
 *
 * @param  string $ip Raw IP address.
 * @return string     Anonymised IP address.
 */
function wpmm_anonymise_ip( $ip ) {
    if ( empty( $ip ) ) {
        return '';
    }

    // IPv6
    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
        $bin  = inet_pton( $ip );
        if ( $bin === false ) { return ''; }
        // Zero the last 10 bytes (80 bits) of the 16-byte address.
        $bin  = substr( $bin, 0, 6 ) . str_repeat( "\x00", 10 );
        return inet_ntop( $bin ) ?: '';
    }

    // IPv4
    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
        $parts    = explode( '.', $ip );
        $parts[3] = '0';
        return implode( '.', $parts );
    }

    return '';
}

// ── GDPR: Daily retention purge ────────────────────────────────────────────────

add_action( 'wpmm_purge_activity_log', 'wpmm_run_activity_log_purge' );

function wpmm_run_activity_log_purge() {
    global $wpdb;
    $s = wpmm_get_settings();

    $days = absint( $s['activity_log_retention_days'] ?? 90 );
    if ( $days < 1 ) {
        return; // 0 = keep forever (admin opted out of auto-purge).
    }

    $activity_table = esc_sql( $wpdb->prefix . 'wpmm_activity_log' );
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
    $wpdb->query( $wpdb->prepare(
        'DELETE FROM ' . $activity_table . ' WHERE logged_at < %s',
        gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) )
    ) );
}

// Schedule daily purge if not already scheduled.
add_action( 'init', function () {
    if ( ! wp_next_scheduled( 'wpmm_purge_activity_log' ) ) {
        wp_schedule_event( time(), 'daily', 'wpmm_purge_activity_log' );
    }
} );

// ═══════════════════════════════════════════════════════════════════════════════
// EVENT HOOKS — Authentication
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Successful login.
 */
add_action( 'wp_login', function ( $user_login, $user ) {
    wpmm_log_activity(
        'user_login',
        WPMM_ACTIVITY_AUTH,
        sprintf( 'User "%s" logged in.', $user_login ),
        [],
        $user->ID
    );
}, 10, 2 );

/**
 * Failed login attempt.
 * Note: at this point the user may not exist, so user_id stays 0.
 */
add_action( 'wp_login_failed', function ( $username ) {
    wpmm_log_activity(
        'login_failed',
        WPMM_ACTIVITY_AUTH,
        sprintf( 'Failed login attempt for username "%s".', sanitize_user( $username ) ),
        [ 'username_attempted' => sanitize_user( $username ) ],
        0
    );
} );

/**
 * Logout.
 */
add_action( 'wp_logout', function ( $user_id ) {
    $u = get_user_by( 'id', $user_id );
    wpmm_log_activity(
        'user_logout',
        WPMM_ACTIVITY_AUTH,
        sprintf( 'User "%s" logged out.', $u ? $u->user_login : "ID:{$user_id}" ),
        [],
        $user_id
    );
} );

/**
 * Password reset request (not the actual reset — just the request).
 */
add_action( 'retrieve_password', function ( $user_login ) {
    wpmm_log_activity(
        'password_reset_requested',
        WPMM_ACTIVITY_AUTH,
        sprintf( 'Password reset requested for "%s".', sanitize_user( $user_login ) ),
        [ 'username' => sanitize_user( $user_login ) ],
        0
    );
} );

/**
 * Password actually changed (via profile page or reset link).
 */
add_action( 'after_password_reset', function ( $user ) {
    wpmm_log_activity(
        'password_changed',
        WPMM_ACTIVITY_AUTH,
        sprintf( 'Password changed for user "%s".', $user->user_login ),
        [],
        $user->ID
    );
} );

// ═══════════════════════════════════════════════════════════════════════════════
// EVENT HOOKS — User Management
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * New user registered / created.
 */
add_action( 'user_register', function ( $user_id ) {
    $u = get_user_by( 'id', $user_id );
    if ( ! $u ) { return; }
    wpmm_log_activity(
        'user_created',
        WPMM_ACTIVITY_USER,
        sprintf( 'New user account created: "%s" (%s).', $u->user_login, $u->user_email ),
        [ 'email' => $u->user_email ],
        get_current_user_id()
    );
} );

/**
 * User deleted.
 */
add_action( 'deleted_user', function ( $user_id, $reassign, $user ) {
    wpmm_log_activity(
        'user_deleted',
        WPMM_ACTIVITY_USER,
        sprintf( 'User account deleted: "%s".', $user->user_login ),
        [ 'deleted_user_email' => $user->user_email ],
        get_current_user_id()
    );
}, 10, 3 );

/**
 * User role changed.
 * Fires on set_user_role — captures both the old and new role.
 */
add_action( 'set_user_role', function ( $user_id, $role, $old_roles ) {
    $u        = get_user_by( 'id', $user_id );
    $old_role = ! empty( $old_roles ) ? $old_roles[0] : 'none';
    wpmm_log_activity(
        'user_role_changed',
        WPMM_ACTIVITY_USER,
        sprintf(
            'Role changed for user "%s": %s → %s.',
            $u ? $u->user_login : "ID:{$user_id}",
            $old_role,
            $role
        ),
        [ 'old_role' => $old_role, 'new_role' => $role ],
        get_current_user_id()
    );
}, 10, 3 );

/**
 * User profile updated (display name, email, etc.).
 * We only log this when a different user edits the profile to avoid noise
 * from users saving their own trivial preferences.
 */
add_action( 'profile_update', function ( $user_id, $old_user_data ) {
    $editor_id = get_current_user_id();
    // Skip if user is editing their own profile — too noisy.
    if ( $editor_id === $user_id ) {
        return;
    }
    $u = get_user_by( 'id', $user_id );
    wpmm_log_activity(
        'user_profile_updated',
        WPMM_ACTIVITY_USER,
        sprintf( 'Profile updated for user "%s" by an administrator.', $u ? $u->user_login : "ID:{$user_id}" ),
        [],
        $editor_id
    );
}, 10, 2 );

// ═══════════════════════════════════════════════════════════════════════════════
// EVENT HOOKS — Site Changes
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Plugin activated.
 */
add_action( 'activated_plugin', function ( $plugin, $network_wide ) {
    $data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
    $name = $data['Name'] ?? $plugin;
    wpmm_log_activity(
        'plugin_activated',
        WPMM_ACTIVITY_SITE,
        sprintf( 'Plugin activated: "%s"%s.', $name, $network_wide ? ' (network-wide)' : '' ),
        [ 'plugin' => $plugin, 'network' => $network_wide ? 'yes' : 'no' ]
    );
}, 10, 2 );

/**
 * Plugin deactivated.
 */
add_action( 'deactivated_plugin', function ( $plugin, $network_wide ) {
    $data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
    $name = $data['Name'] ?? $plugin;
    wpmm_log_activity(
        'plugin_deactivated',
        WPMM_ACTIVITY_SITE,
        sprintf( 'Plugin deactivated: "%s"%s.', $name, $network_wide ? ' (network-wide)' : '' ),
        [ 'plugin' => $plugin, 'network' => $network_wide ? 'yes' : 'no' ]
    );
}, 10, 2 );

/**
 * Plugin deleted.
 * Fires after the plugin folder has been removed from disk.
 */
add_action( 'deleted_plugin', function ( $plugin_file, $deleted ) {
    if ( ! $deleted ) { return; }
    wpmm_log_activity(
        'plugin_deleted',
        WPMM_ACTIVITY_SITE,
        sprintf( 'Plugin deleted: "%s".', $plugin_file ),
        [ 'plugin' => $plugin_file ]
    );
}, 10, 2 );

/**
 * Theme switched.
 */
add_action( 'switch_theme', function ( $new_name, $new_theme, $old_theme ) {
    wpmm_log_activity(
        'theme_switched',
        WPMM_ACTIVITY_SITE,
        sprintf( 'Theme switched from "%s" to "%s".', $old_theme->get( 'Name' ), $new_name ),
        [ 'old_theme' => $old_theme->get( 'Name' ), 'new_theme' => $new_name ]
    );
}, 10, 3 );

/**
 * WordPress core updated.
 * Fires after a successful core update.
 */
add_action( '_core_updated_successfully', function ( $wp_version ) {
    wpmm_log_activity(
        'core_updated',
        WPMM_ACTIVITY_SITE,
        sprintf( 'WordPress core updated to version %s.', $wp_version ),
        [ 'new_version' => $wp_version ]
    );
} );

/**
 * Greenskeeper settings saved.
 * Log when any Greenskeeper setting is changed so there's an audit trail.
 */
add_action( 'update_option_wpmm_settings', function ( $old_value, $new_value ) {
    wpmm_log_activity(
        'greenskeeper_settings_saved',
        WPMM_ACTIVITY_SITE,
        'Greenskeeper settings updated.',
        []
    );
}, 10, 2 );

/**
 * General WordPress options saved (covers Settings > General, Reading, etc.).
 * We only log a curated list of option names to avoid noise.
 */
add_action( 'updated_option', function ( $option_name ) {
    $watched = [
        'blogname'            => 'Site title changed.',
        'blogdescription'     => 'Site tagline changed.',
        'siteurl'             => 'Site URL changed.',
        'home'                => 'Home URL changed.',
        'admin_email'         => 'Admin email address changed.',
        'default_role'        => 'Default user role changed.',
        'permalink_structure' => 'Permalink structure changed.',
        'blog_public'         => 'Search engine visibility setting changed.',
        'users_can_register'  => 'User registration setting changed.',
    ];

    if ( ! isset( $watched[ $option_name ] ) ) {
        return;
    }

    wpmm_log_activity(
        'option_updated',
        WPMM_ACTIVITY_SITE,
        $watched[ $option_name ],
        [ 'option_name' => $option_name ]
    );
} );

// ═══════════════════════════════════════════════════════════════════════════════
// GDPR: Data export helper
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Export all activity log rows for a given user as a CSV-formatted string.
 * Used to satisfy GDPR Subject Access Requests.
 *
 * @param  int    $user_id  WordPress user ID.
 * @return string           CSV data or empty string if no records found.
 */
function wpmm_activity_log_export_csv( $user_id = 0 ) {
    global $wpdb;
    $activity_table = esc_sql( $wpdb->prefix . 'wpmm_activity_log' );

    if ( $user_id ) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $rows = $wpdb->get_results( $wpdb->prepare(
            'SELECT * FROM ' . $activity_table . ' WHERE user_id = %d ORDER BY logged_at DESC',
            $user_id
        ), ARRAY_A );
    } else {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $rows = $wpdb->get_results(
            'SELECT * FROM ' . $activity_table . ' ORDER BY logged_at DESC',
            ARRAY_A
        );
    }

    if ( empty( $rows ) ) {
        return '';
    }

    $output = fopen( 'php://temp', 'r+' );
    fputcsv( $output, array_keys( $rows[0] ) ); // header row
    foreach ( $rows as $row ) {
        fputcsv( $output, $row );
    }
    rewind( $output );
    $csv = stream_get_contents( $output );
    fclose( $output );
    return $csv;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AJAX: Activity log page handlers
// ═══════════════════════════════════════════════════════════════════════════════

add_action( 'wp_ajax_wpmm_activity_log_get',    'wpmm_ajax_activity_log_get' );
add_action( 'wp_ajax_wpmm_activity_log_delete', 'wpmm_ajax_activity_log_delete' );
add_action( 'wp_ajax_wpmm_activity_log_export', 'wpmm_ajax_activity_log_export' );

/**
 * Return paginated activity log rows as JSON.
 */
function wpmm_ajax_activity_log_get() {
    wpmm_ajax_cap_check();
    global $wpdb;

    // phpcs:disable WordPress.Security.NonceVerification.Missing -- verified via wpmm_ajax_cap_check()
    $page     = max( 1, absint( $_POST['page']     ?? 1 ) );
    $per_page = absint( $_POST['per_page'] ?? 50 );
    $per_page = in_array( $per_page, [ 25, 50, 100 ], true ) ? $per_page : 50;
    $category = sanitize_key( $_POST['category'] ?? '' );
    $search   = sanitize_text_field( wp_unslash( $_POST['search'] ?? '' ) );
    $date_from = sanitize_text_field( wp_unslash( $_POST['date_from'] ?? '' ) );
    $date_to   = sanitize_text_field( wp_unslash( $_POST['date_to']   ?? '' ) );
    // phpcs:enable

    $activity_table = esc_sql( $wpdb->prefix . 'wpmm_activity_log' );
    $where  = ' WHERE 1=1';
    $args   = [];

    if ( $category ) {
        $where .= ' AND category = %s';
        $args[] = $category;
    }
    if ( $search ) {
        $where .= ' AND (summary LIKE %s OR user_login LIKE %s OR ip_address LIKE %s)';
        $like   = '%' . $wpdb->esc_like( $search ) . '%';
        $args[] = $like;
        $args[] = $like;
        $args[] = $like;
    }
    if ( $date_from ) {
        $where .= ' AND logged_at >= %s';
        $args[] = $date_from . ' 00:00:00';
    }
    if ( $date_to ) {
        $where .= ' AND logged_at <= %s';
        $args[] = $date_to . ' 23:59:59';
    }

    $offset = ( $page - 1 ) * $per_page;

    $count_sql = 'SELECT COUNT(*) FROM ' . $activity_table . $where;
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
    $total = (int) ( $args ? $wpdb->get_var( $wpdb->prepare( $count_sql, $args ) ) : $wpdb->get_var( $count_sql ) );

    $rows_sql = 'SELECT * FROM ' . $activity_table . $where . ' ORDER BY logged_at DESC LIMIT %d OFFSET %d';
    $row_args = array_merge( $args, [ $per_page, $offset ] );
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
    $rows = $wpdb->get_results( $wpdb->prepare( $rows_sql, $row_args ) );

    wp_send_json_success( [
        'rows'       => $rows,
        'total'      => $total,
        'page'       => $page,
        'per_page'   => $per_page,
        'total_pages'=> (int) ceil( $total / $per_page ),
    ] );
}

/**
 * Delete one or all activity log rows.
 */
function wpmm_ajax_activity_log_delete() {
    wpmm_ajax_cap_check();
    global $wpdb;

    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified via wpmm_ajax_cap_check()
    $ids      = array_map( 'absint', (array) ( $_POST['ids'] ?? [] ) );
    $clear_all = ! empty( $_POST['clear_all'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

    $activity_table = esc_sql( $wpdb->prefix . 'wpmm_activity_log' );

    if ( $clear_all ) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.NotPrepared
        $wpdb->query( 'TRUNCATE TABLE ' . $activity_table );
        wp_send_json_success( [ 'message' => 'Activity log cleared.' ] );
    }

    if ( empty( $ids ) ) {
        wp_send_json_error( 'No IDs provided.' );
    }

    $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
    $deleted = $wpdb->query(
        $wpdb->prepare( 'DELETE FROM ' . $activity_table . ' WHERE id IN (' . $placeholders . ')', $ids )
    );
    wp_send_json_success( [ 'deleted' => $deleted ] );
}

/**
 * Stream a CSV download of the full activity log.
 * Must be called as a direct page request (not an AJAX response),
 * so we handle it via admin_post_ hook.
 */
add_action( 'admin_post_wpmm_activity_export', function () {
    if ( ! current_user_can( wpmm_required_cap() ) ) {
        wp_die( 'Permission denied.' );
    }
    check_admin_referer( 'wpmm_activity_export' );

    $csv = wpmm_activity_log_export_csv();

    if ( empty( $csv ) ) {
        wp_die( 'No activity log data to export.' );
    }

    $filename = 'greenskeeper-activity-log-' . gmdate( 'Y-m-d' ) . '.csv';

    header( 'Content-Type: text/csv; charset=UTF-8' );
    header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
    header( 'Pragma: no-cache' );
    header( 'Expires: 0' );

    // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV binary download, no HTML context.
    echo "\xEF\xBB\xBF"; // UTF-8 BOM for Excel compatibility.
    // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    echo $csv;
    exit;
} );

/**
 * AJAX export wrapper — returns CSV as a base64 string for JS-triggered download.
 */
function wpmm_ajax_activity_log_export() {
    wpmm_ajax_cap_check();
    $csv = wpmm_activity_log_export_csv();
    if ( empty( $csv ) ) {
        wp_send_json_error( 'No data to export.' );
    }
    wp_send_json_success( [
        'csv'      => base64_encode( $csv ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- used for safe JSON transport only.
        'filename' => 'greenskeeper-activity-log-' . gmdate( 'Y-m-d' ) . '.csv',
    ] );
}

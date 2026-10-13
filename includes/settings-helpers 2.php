<?php
/**
 * Settings helpers — read/write the wpmm_settings option.
 * Loaded early so email.php and admin pages can both use wpmm_get_settings().
 */
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Return the full settings array with defaults filled in.
 */
function wpmm_get_settings() {
    $defaults = [
        'company_name'                => '',
        'logo_url'                    => '',
        'client_email'                => get_option( 'wpmm_client_email', '' ),
        'default_admin_id'            => 0,
        // Activity log defaults — explicit 0/1 integers prevent ambiguous null/missing/bool state.
        'activity_log_enabled'        => 0,
        'activity_log_full_ip'        => 0,  // 0 = anonymise (GDPR default)
        'activity_log_retention_days' => 90,
        // Admin notification email defaults.
        'notify_all_success'          => 0,  // off by default — low noise
        'notify_partial_success'      => 1,  // on — actionable
        'notify_all_failed'           => 1,  // on — critical
        // SMTP conflict resolution — 0 = Greenskeeper is sender of record (default).
        'smtp_defer_to_plugin'        => 0,
    ];
    // Allow other modules (e.g. spam-filter.php) to register their own defaults.
    $defaults = apply_filters( 'wpmm_settings_defaults', $defaults );
    $saved    = get_option( 'wpmm_settings', [] );
    return wp_parse_args( $saved, $defaults );
}

/**
 * Persist the settings array.
 */
function wpmm_save_settings( array $settings ) {
    update_option( 'wpmm_settings', $settings, false );
}

/**
 * Return the WP_User object for the default administrator, or null.
 */
function wpmm_get_default_admin() {
    $s  = wpmm_get_settings();
    $id = absint( $s['default_admin_id'] ?? 0 );
    if ( ! $id ) { return null; }
    $user = get_user_by( 'id', $id );
    return ( $user && user_can( $user, 'manage_options' ) ) ? $user : null;
}

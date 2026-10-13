<?php
/**
 * Greenskeeper — External Update Detector
 *
 * Detects plugin and theme version changes made outside Greenskeeper
 * by comparing a stored version snapshot against currently installed
 * versions on every admin page load. When a change is detected it is
 * logged to wpmm_update_log with a session prefix of 'ext-detect-'.
 *
 * Covers proprietary updaters (Avada, Divi, Elementor Pro, WP Rocket,
 * Gravity Forms, ACF Pro, etc.) that do not fire the standard WordPress
 * upgrader_process_complete hook.
 *
 * @package Greenskeeper
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

// ── Product family map ────────────────────────────────────────────────────────
// Maps slug substrings to a human-readable product family name.
// Pattern matching is case-insensitive substring — first match wins.
function wpmm_get_product_families() {
    return [
        // Page builders & themes
        'fusion'           => 'Avada Theme Suite',
        'avada'            => 'Avada Theme Suite',
        'divi'             => 'Divi by Elegant Themes',
        'et-'              => 'Divi by Elegant Themes',
        'elegantthemes'    => 'Divi by Elegant Themes',
        'elementor'        => 'Elementor',
        'beaver-builder'   => 'Beaver Builder',
        'bb-plugin'        => 'Beaver Builder',
        'bb-theme'         => 'Beaver Builder',
        'fl-builder'       => 'Beaver Builder',
        'js_composer'      => 'WP Bakery Page Builder',
        'wpbakery'         => 'WP Bakery Page Builder',
        'oxygen'           => 'Oxygen Builder',
        'bricks'           => 'Bricks Builder',
        'flatsome'         => 'Flatsome Theme',
        'enfold'           => 'Enfold Theme',
        'the7'             => 'The7 Theme',

        // Forms
        'gravityforms'     => 'Gravity Forms',
        'gravity-forms'    => 'Gravity Forms',
        'wpforms'          => 'WPForms',
        'ninja-forms'      => 'Ninja Forms',
        'formidable'       => 'Formidable Forms',

        // SEO
        'aioseo'           => 'All in One SEO',
        'all-in-one-seo'   => 'All in One SEO',
        'wordpress-seo'    => 'Yoast SEO',
        'yoast'            => 'Yoast SEO',
        'rank-math'        => 'RankMath',
        'rankmath'         => 'RankMath',

        // Events
        'tribe'            => 'The Events Calendar Suite',
        'the-events'       => 'The Events Calendar Suite',
        'events-calendar'  => 'The Events Calendar Suite',

        // Automattic products
        'woocommerce'      => 'Automattic · WooCommerce',
        'jetpack'          => 'Automattic · Jetpack',
        'akismet'          => 'Automattic · Akismet',
        'wordpress-com'    => 'Automattic · WordPress.com',

        // Performance & optimization
        'wp-rocket'        => 'WP Rocket',
        'imagify'          => 'Imagify',
        'shortpixel'       => 'ShortPixel',
        'smush'            => 'WPMU Dev · Smush',
        'wpmu'             => 'WPMU Dev',
        'autoptimize'      => 'Autoptimize',
        'litespeed'        => 'LiteSpeed Cache',
        'perfmatters'      => 'Perfmatters',
        'asset-cleanup'    => 'Asset CleanUp',

        // Security
        'sucuri'           => 'Sucuri Security',
        'ithemes-security' => 'iThemes Security',
        'wordfence'        => 'Wordfence',
        'really-simple-ssl'=> 'Really Simple SSL',

        // ACF
        'advanced-custom-fields' => 'Advanced Custom Fields',
        'acf-'             => 'Advanced Custom Fields',
        'acf/'             => 'Advanced Custom Fields',

        // Multilingual
        'wpml'             => 'WPML',
        'polylang'         => 'Polylang',

        // LMS & Membership
        'learndash'        => 'LearnDash',
        'memberpress'      => 'MemberPress',
        'lifterlms'        => 'LifterLMS',
        'easy-digital-downloads' => 'Easy Digital Downloads',

        // CRM & Marketing
        'fluentcrm'        => 'FluentCRM',
        'mailchimp'        => 'Mailchimp',
        'hubspot'          => 'HubSpot',
        'monsterinsights'  => 'MonsterInsights',

        // Search & filtering
        'searchwp'         => 'SearchWP',
        'facetwp'          => 'FacetWP',

        // Hosting platforms
        'wpe-'             => 'WP Engine Platform',
        'wpengine'         => 'WP Engine Platform',
        'kinsta'           => 'Kinsta Platform',
        'cloudflare'       => 'Cloudflare',

        // Backup
        'updraftplus'      => 'UpdraftPlus',
        'backupbuddy'      => 'BackupBuddy',
        'mainwp'           => 'MainWP',
    ];
}

/**
 * Resolve the product family name for a given plugin slug.
 *
 * @param  string $slug Plugin slug or file path.
 * @return string       Family name or 'Other External Updates'.
 */
function wpmm_resolve_product_family( $slug ) {
    $slug     = strtolower( $slug );
    $families = wpmm_get_product_families();
    foreach ( $families as $pattern => $family ) {
        if ( strpos( $slug, strtolower( $pattern ) ) !== false ) {
            return $family;
        }
    }
    return 'Other External Updates';
}

// ── Version snapshot ──────────────────────────────────────────────────────────

/**
 * Take a snapshot of all currently installed plugin and theme versions.
 * Stored as a site option so it persists across page loads.
 *
 * @return array [ 'plugins' => [ slug => version ], 'themes' => [ slug => version ] ]
 */
function wpmm_take_version_snapshot() {
    if ( ! function_exists( 'get_plugins' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $plugins = get_plugins();
    $snap    = [];
    foreach ( $plugins as $file => $data ) {
        $snap[ $file ] = $data['Version'] ?? '';
    }

    $themes      = wp_get_themes();
    $theme_snap  = [];
    foreach ( $themes as $slug => $theme ) {
        $theme_snap[ $slug ] = $theme->get( 'Version' );
    }

    return [
        'plugins'   => $snap,
        'themes'    => $theme_snap,
        'timestamp' => time(),
    ];
}

/**
 * Get the stored version snapshot.
 *
 * @return array|false Stored snapshot or false if none exists.
 */
function wpmm_get_stored_snapshot() {
    return get_option( 'wpmm_version_snapshot', false );
}

/**
 * Save a new version snapshot.
 *
 * @param array $snapshot Snapshot from wpmm_take_version_snapshot().
 */
function wpmm_save_version_snapshot( $snapshot ) {
    update_option( 'wpmm_version_snapshot', $snapshot, false );
}

/**
 * Compare stored snapshot against current versions and log any changes
 * that were not made by Greenskeeper (i.e. not already in wpmm_update_log
 * for a recent Greenskeeper session).
 *
 * Called on admin_init so it runs on every admin page load.
 */
function wpmm_detect_external_version_changes() {
    // Only run in admin and only for users who can manage options.
    if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $stored = wpmm_get_stored_snapshot();

    // First run — just take a snapshot, nothing to compare against yet.
    if ( ! $stored ) {
        wpmm_save_version_snapshot( wpmm_take_version_snapshot() );
        return;
    }

    $current = wpmm_take_version_snapshot();
    $changes = [];

    // ── Compare plugins ───────────────────────────────────────────────────────
    foreach ( $current['plugins'] as $file => $version ) {
        $old_version = $stored['plugins'][ $file ] ?? null;
        if ( $old_version === null ) {
            // Newly installed plugin — not an update, skip.
            continue;
        }
        if ( $version !== $old_version && version_compare( $version, $old_version, '>' ) ) {
            $changes[] = [
                'type'        => 'plugin',
                'file'        => $file,
                'slug'        => dirname( $file ),
                'old_version' => $old_version,
                'new_version' => $version,
            ];
        }
    }

    // ── Compare themes ────────────────────────────────────────────────────────
    foreach ( $current['themes'] as $slug => $version ) {
        $old_version = $stored['themes'][ $slug ] ?? null;
        if ( $old_version === null ) { continue; }
        if ( $version !== $old_version && version_compare( $version, $old_version, '>' ) ) {
            $changes[] = [
                'type'        => 'theme',
                'file'        => $slug,
                'slug'        => $slug,
                'old_version' => $old_version,
                'new_version' => $version,
            ];
        }
    }

    if ( empty( $changes ) ) {
        // No changes — update snapshot timestamp and return.
        wpmm_save_version_snapshot( $current );
        return;
    }

    // ── Filter out changes already logged by Greenskeeper ─────────────────────
    global $wpdb;
    $log_table   = esc_sql( $wpdb->prefix . 'wpmm_update_log' );
    $cutoff_time = gmdate( 'Y-m-d H:i:s', $stored['timestamp'] );
    $session_id  = 'ext-detect-' . gmdate( 'YmdHis' );

    foreach ( $changes as $change ) {
        $slug = $change['slug'];

        // Check if Greenskeeper already logged this update.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $already_logged = $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$log_table}
             WHERE item_slug = %s
             AND new_version = %s
             AND updated_at >= %s",
            $slug,
            $change['new_version'],
            $cutoff_time
        ) );

        if ( $already_logged ) {
            continue; // Greenskeeper handled this — skip.
        }

        // Get the plugin display name.
        if ( $change['type'] === 'plugin' ) {
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $all_plugins = get_plugins();
            $name        = $all_plugins[ $change['file'] ]['Name'] ?? ucwords( str_replace( '-', ' ', $slug ) );
        } else {
            $theme = wp_get_theme( $slug );
            $name  = $theme->get( 'Name' ) ?: ucwords( str_replace( '-', ' ', $slug ) );
        }

        // Resolve product family for grouping in the email.
        $family = wpmm_resolve_product_family( $change['file'] );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $log_table,
            [
                'session_id'  => $session_id,
                'item_name'   => $name,
                'item_type'   => $change['type'],
                'item_slug'   => $slug,
                'old_version' => $change['old_version'],
                'new_version' => $change['new_version'],
                'status'      => 'success',
                'error_code'  => '',
                'message'     => 'Updated outside Greenskeeper. Family: ' . $family,
                'updated_at'  => current_time( 'mysql' ),
            ]
        );
    }

    // Save the new snapshot after logging changes.
    wpmm_save_version_snapshot( $current );
}
add_action( 'admin_init', 'wpmm_detect_external_version_changes' );

/**
 * Get external update rows for the email report, grouped by product family.
 * Returns an associative array: [ 'Family Name' => [ rows... ] ]
 *
 * @param  string $since MySQL datetime — only return updates after this time.
 * @return array
 */
function wpmm_get_external_updates_grouped( $since = '' ) {
    global $wpdb;
    $log_table = esc_sql( $wpdb->prefix . 'wpmm_update_log' );

    $where = "WHERE session_id LIKE 'ext-%'";
    $args  = [];

    if ( $since ) {
        $where .= ' AND updated_at >= %s';
        $args[] = $since;
    }

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $rows = $args
        ? $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$log_table} {$where} ORDER BY updated_at ASC", ...$args ) )
        : $wpdb->get_results( "SELECT * FROM {$log_table} {$where} ORDER BY updated_at ASC" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared

    if ( empty( $rows ) ) {
        return [];
    }

    $grouped = [];
    foreach ( $rows as $row ) {
        // Resolve family from message field (stored at log time) or re-resolve from slug.
        $family = 'Other External Updates';
        if ( ! empty( $row->message ) && strpos( $row->message, 'Family: ' ) !== false ) {
            $family = trim( str_replace( 'Updated outside Greenskeeper. Family: ', '', $row->message ) );
        } else {
            $family = wpmm_resolve_product_family( $row->item_slug ?? $row->item_name ?? '' );
        }
        $grouped[ $family ][] = $row;
    }

    // Sort: Other External Updates always last.
    if ( isset( $grouped['Other External Updates'] ) ) {
        $other = $grouped['Other External Updates'];
        unset( $grouped['Other External Updates'] );
        $grouped['Other External Updates'] = $other;
    }

    return $grouped;
}

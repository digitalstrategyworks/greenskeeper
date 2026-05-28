<?php
/**
 * Greenskeeper — System Info page renderer.
 *
 * Displays server environment, WordPress environment, active theme,
 * and active plugins — with a copyable plain-text block for support tickets.
 *
 * @package Greenskeeper
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Render the System Info page.
 */
function wpmm_render_system_info() {
    if ( ! current_user_can( wpmm_required_cap() ) ) {
        wp_die( esc_html__( 'You do not have permission to view this page.', 'greenskeeper' ) );
    }

    // ── Collect server environment data ───────────────────────────────────────
    $php_version     = phpversion();
    $php_max_input   = ini_get( 'max_input_vars' );
    $php_post_size   = ini_get( 'post_max_size' );
    $gd_installed    = extension_loaded( 'gd' );
    $zip_installed   = extension_loaded( 'zip' );
    $curl_installed  = extension_loaded( 'curl' );
    $mbstring        = extension_loaded( 'mbstring' );
    $os              = PHP_OS;
    $software        = isset( $_SERVER['SERVER_SOFTWARE'] )
        ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
        : 'Unknown';

    // ── Collect WordPress environment data ────────────────────────────────────
    global $wpdb;
    $wp_version       = get_bloginfo( 'version' );
    $site_url         = get_site_url();
    $home_url         = get_home_url();
    $is_multisite     = is_multisite();
    $max_upload       = size_format( wp_max_upload_size() );
    $memory_limit     = WP_MEMORY_LIMIT;
    $permalink        = get_option( 'permalink_structure' ) ?: 'Default (Plain)';
    $language         = get_locale();
    $timezone         = wp_timezone_string();
    $admin_email      = get_option( 'admin_email' );
    $debug_mode       = defined( 'WP_DEBUG' ) && WP_DEBUG ? 'Active' : 'Inactive';
    $db_version       = $wpdb->db_version();
    $table_prefix     = $wpdb->prefix;

    // ── Active theme ──────────────────────────────────────────────────────────
    $theme            = wp_get_theme();
    $theme_name       = $theme->get( 'Name' );
    $theme_version    = $theme->get( 'Version' );
    $theme_author     = $theme->get( 'Author' );
    $theme_uri        = $theme->get( 'ThemeURI' );
    $is_child         = is_child_theme();

    // ── Active plugins ────────────────────────────────────────────────────────
    $active_plugins = get_option( 'active_plugins', [] );
    if ( $is_multisite ) {
        $network_plugins = array_keys( get_site_option( 'active_sitewide_plugins', [] ) );
        $active_plugins  = array_unique( array_merge( $active_plugins, $network_plugins ) );
    }
    sort( $active_plugins );

    $plugins_data = [];
    foreach ( $active_plugins as $plugin_file ) {
        $data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_file, false, false );
        if ( ! empty( $data['Name'] ) ) {
            $plugins_data[] = [
                'name'    => $data['Name'],
                'version' => $data['Version'] ?? '',
                'author'  => wp_strip_all_tags( $data['Author'] ?? '' ),
                'uri'     => $data['PluginURI'] ?? '',
            ];
        }
    }

    // ── Build plain-text copy block ───────────────────────────────────────────
    $copy_text  = "### Server Environment ###\n";
    $copy_text .= "Operating System: {$os}\n";
    $copy_text .= "Software: {$software}\n";
    $copy_text .= "PHP Version: {$php_version}\n";
    $copy_text .= "PHP Max Input Vars: {$php_max_input}\n";
    $copy_text .= "PHP Max Post Size: {$php_post_size}\n";
    $copy_text .= "GD Installed: " . ( $gd_installed ? 'Yes' : 'No' ) . "\n";
    $copy_text .= "Zip Installed: " . ( $zip_installed ? 'Yes' : 'No' ) . "\n";
    $copy_text .= "cURL Installed: " . ( $curl_installed ? 'Yes' : 'No' ) . "\n";
    $copy_text .= "mbstring Installed: " . ( $mbstring ? 'Yes' : 'No' ) . "\n\n";

    $copy_text .= "### WordPress Environment ###\n";
    $copy_text .= "Version: {$wp_version}\n";
    $copy_text .= "Site URL: {$site_url}\n";
    $copy_text .= "Home URL: {$home_url}\n";
    $copy_text .= "WP_MULTISITE: " . ( $is_multisite ? 'Yes' : 'No' ) . "\n";
    $copy_text .= "Max Upload Size: {$max_upload}\n";
    $copy_text .= "Memory Limit: {$memory_limit}\n";
    $copy_text .= "Permalink Structure: {$permalink}\n";
    $copy_text .= "Language: {$language}\n";
    $copy_text .= "Timezone: {$timezone}\n";
    $copy_text .= "Admin Email: {$admin_email}\n";
    $copy_text .= "Debug Mode: {$debug_mode}\n";
    $copy_text .= "Database Version: {$db_version}\n";
    $copy_text .= "Table Prefix: {$table_prefix}\n\n";

    $copy_text .= "### Active Theme ###\n";
    $copy_text .= "Name: {$theme_name}\n";
    $copy_text .= "Version: {$theme_version}\n";
    $copy_text .= "Author: {$theme_author}\n";
    $copy_text .= "Child Theme: " . ( $is_child ? 'Yes' : 'No' ) . "\n\n";

    $copy_text .= "### Active Plugins ###\n";
    foreach ( $plugins_data as $p ) {
        $copy_text .= "{$p['name']} {$p['version']} by {$p['author']}\n";
    }

    $copy_text .= "\n### Greenskeeper ###\n";
    $copy_text .= "Version: " . WPMM_VERSION . "\n";
    ?>
    <div class="wrap wpmm-wrap">
        <?php wpmm_page_header( WPMM_SLUG_SYSINFO ); ?>

        <div style="display:grid;grid-template-columns:1fr 280px;gap:20px;align-items:start;">

            <!-- Main column -->
            <div>

                <!-- Server Environment -->
                <div class="wpmm-card" style="margin-bottom:20px;">
                    <h2 class="wpmm-card-title">
                        <span class="dashicons dashicons-admin-tools"></span> Server Environment
                    </h2>
                    <table class="wpmm-sysinfo-table">
                        <?php wpmm_sysinfo_row( 'Operating System', $os ); ?>
                        <?php wpmm_sysinfo_row( 'Software', $software ); ?>
                        <?php wpmm_sysinfo_row( 'PHP Version', $php_version, version_compare( $php_version, '8.0', '>=' ) ? 'good' : 'warn' ); ?>
                        <?php wpmm_sysinfo_row( 'PHP Max Input Vars', $php_max_input ); ?>
                        <?php wpmm_sysinfo_row( 'PHP Max Post Size', $php_post_size ); ?>
                        <?php wpmm_sysinfo_row( 'GD Installed', $gd_installed ? 'Yes' : 'No', $gd_installed ? 'good' : 'warn' ); ?>
                        <?php wpmm_sysinfo_row( 'Zip Installed', $zip_installed ? 'Yes' : 'No', $zip_installed ? 'good' : 'warn' ); ?>
                        <?php wpmm_sysinfo_row( 'cURL Installed', $curl_installed ? 'Yes' : 'No', $curl_installed ? 'good' : 'warn' ); ?>
                        <?php wpmm_sysinfo_row( 'mbstring Installed', $mbstring ? 'Yes' : 'No', $mbstring ? 'good' : 'warn' ); ?>
                    </table>
                </div>

                <!-- WordPress Environment -->
                <div class="wpmm-card" style="margin-bottom:20px;">
                    <h2 class="wpmm-card-title">
                        <span class="dashicons dashicons-wordpress"></span> WordPress Environment
                    </h2>
                    <table class="wpmm-sysinfo-table">
                        <?php wpmm_sysinfo_row( 'Version', $wp_version, version_compare( $wp_version, '6.0', '>=' ) ? 'good' : 'warn' ); ?>
                        <?php wpmm_sysinfo_row( 'Site URL', esc_url( $site_url ) ); ?>
                        <?php wpmm_sysinfo_row( 'Home URL', esc_url( $home_url ) ); ?>
                        <?php wpmm_sysinfo_row( 'WP_MULTISITE', $is_multisite ? 'Yes' : 'No' ); ?>
                        <?php wpmm_sysinfo_row( 'Max Upload Size', $max_upload ); ?>
                        <?php wpmm_sysinfo_row( 'Memory Limit', $memory_limit ); ?>
                        <?php wpmm_sysinfo_row( 'Permalink Structure', $permalink ); ?>
                        <?php wpmm_sysinfo_row( 'Language', $language ); ?>
                        <?php wpmm_sysinfo_row( 'Timezone', $timezone ); ?>
                        <?php wpmm_sysinfo_row( 'Admin Email', $admin_email ); ?>
                        <?php wpmm_sysinfo_row( 'Debug Mode', $debug_mode, $debug_mode === 'Active' ? 'warn' : 'good' ); ?>
                        <?php wpmm_sysinfo_row( 'Database Version', $db_version ); ?>
                        <?php wpmm_sysinfo_row( 'Table Prefix', $table_prefix ); ?>
                    </table>
                </div>

                <!-- Active Theme -->
                <div class="wpmm-card" style="margin-bottom:20px;">
                    <h2 class="wpmm-card-title">
                        <span class="dashicons dashicons-admin-appearance"></span> Active Theme
                    </h2>
                    <table class="wpmm-sysinfo-table">
                        <?php wpmm_sysinfo_row( 'Name', $theme_name ); ?>
                        <?php wpmm_sysinfo_row( 'Version', $theme_version ); ?>
                        <?php wpmm_sysinfo_row( 'Author', $theme_author ); ?>
                        <?php if ( $theme_uri ) : ?>
                            <?php wpmm_sysinfo_row( 'Theme URI', '<a href="' . esc_url( $theme_uri ) . '" target="_blank">' . esc_html( $theme_uri ) . '</a>' ); ?>
                        <?php endif; ?>
                        <?php wpmm_sysinfo_row( 'Child Theme', $is_child ? 'Yes' : 'No', $is_child ? 'good' : '' ); ?>
                    </table>
                </div>

                <!-- Active Plugins -->
                <div class="wpmm-card">
                    <h2 class="wpmm-card-title">
                        <span class="dashicons dashicons-admin-plugins"></span>
                        Active Plugins
                        <span style="font-size:13px;font-weight:400;color:var(--wpmm-gray);margin-left:8px;">
                            (<?php echo count( $plugins_data ); ?>)
                        </span>
                    </h2>
                    <table class="wpmm-sysinfo-table">
                        <thead>
                            <tr>
                                <th style="text-align:left;padding:8px 14px;font-size:12px;color:var(--wpmm-gray);
                                           border-bottom:2px solid var(--wpmm-border);font-weight:700;width:40%;">Plugin</th>
                                <th style="text-align:left;padding:8px 14px;font-size:12px;color:var(--wpmm-gray);
                                           border-bottom:2px solid var(--wpmm-border);font-weight:700;width:15%;">Version</th>
                                <th style="text-align:left;padding:8px 14px;font-size:12px;color:var(--wpmm-gray);
                                           border-bottom:2px solid var(--wpmm-border);font-weight:700;">Author</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ( $plugins_data as $p ) : ?>
                            <tr>
                                <td style="padding:9px 14px;border-bottom:1px solid var(--wpmm-border);font-size:13px;">
                                    <?php if ( $p['uri'] ) : ?>
                                        <a href="<?php echo esc_url( $p['uri'] ); ?>" target="_blank" style="color:var(--wpmm-blue);text-decoration:none;">
                                            <?php echo esc_html( $p['name'] ); ?>
                                        </a>
                                    <?php else : ?>
                                        <?php echo esc_html( $p['name'] ); ?>
                                    <?php endif; ?>
                                </td>
                                <td style="padding:9px 14px;border-bottom:1px solid var(--wpmm-border);font-size:13px;
                                           color:var(--wpmm-gray);font-family:monospace;">
                                    <?php echo esc_html( $p['version'] ); ?>
                                </td>
                                <td style="padding:9px 14px;border-bottom:1px solid var(--wpmm-border);font-size:13px;
                                           color:var(--wpmm-text-light);">
                                    <?php echo esc_html( $p['author'] ); ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            </div><!-- /main column -->

            <!-- Sidebar: copy block -->
            <div>
                <div class="wpmm-card" style="position:sticky;top:32px;">
                    <h2 class="wpmm-card-title" style="font-size:14px;">
                        <span class="dashicons dashicons-clipboard"></span> Copy &amp; Paste Info
                    </h2>
                    <p style="font-size:12px;color:var(--wpmm-text-light);margin:0 0 10px;line-height:1.5;">
                        Copy the info below as simple text. Use it when submitting support tickets to plugin developers.
                    </p>
                    <textarea id="wpmm-sysinfo-copy"
                              style="width:100%;height:280px;font-family:monospace;font-size:11px;
                                     border:1px solid var(--wpmm-border);border-radius:4px;
                                     padding:10px;resize:vertical;line-height:1.5;color:#374151;"
                              readonly><?php echo esc_textarea( $copy_text ); ?></textarea>
                    <button type="button" id="wpmm-sysinfo-copy-btn"
                            class="wpmm-btn wpmm-btn-primary"
                            style="width:100%;margin-top:10px;justify-content:center;">
                        <span class="dashicons dashicons-clipboard" style="margin:0 4px 0 0;"></span>
                        Copy to Clipboard
                    </button>
                    <p id="wpmm-sysinfo-copy-msg"
                       style="display:none;text-align:center;color:var(--wpmm-green);
                              font-size:12px;margin:6px 0 0;">
                        &#10003; Copied!
                    </p>
                </div>
            </div>

        </div><!-- /grid -->
    </div>
    <?php
}

/**
 * Render a single system info table row.
 *
 * @param string $label  Row label.
 * @param string $value  Row value (may contain HTML).
 * @param string $status 'good', 'warn', or '' for neutral.
 */
function wpmm_sysinfo_row( $label, $value, $status = '' ) {
    $indicator = '';
    if ( $status === 'good' ) {
        $indicator = '<span class="dashicons dashicons-yes-alt" style="color:#16a34a;font-size:16px;width:16px;height:16px;vertical-align:middle;margin-left:6px;"></span>';
    } elseif ( $status === 'warn' ) {
        $indicator = '<span class="dashicons dashicons-warning" style="color:#f59e0b;font-size:16px;width:16px;height:16px;vertical-align:middle;margin-left:6px;"></span>';
    }
    echo '<tr>';
    echo '<td style="padding:9px 14px;border-bottom:1px solid var(--wpmm-border);font-size:13px;font-weight:600;color:var(--wpmm-text);width:45%;white-space:nowrap;">' . esc_html( $label ) . '</td>';
    echo '<td style="padding:9px 14px;border-bottom:1px solid var(--wpmm-border);font-size:13px;color:var(--wpmm-text-light);">' . wp_kses_post( $value ) . $indicator . '</td>';
    echo '</tr>';
}

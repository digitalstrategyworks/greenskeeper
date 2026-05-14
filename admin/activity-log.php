<?php
/**
 * Greenskeeper — Site Activity Log admin page renderer.
 *
 * @package Greenskeeper
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Render the Site Activity Log page.
 */
function wpmm_render_activity_log() {
    if ( ! current_user_can( wpmm_required_cap() ) ) {
        wp_die( esc_html__( 'You do not have permission to view this page.', 'greenskeeper' ) );
    }

    $s                = wpmm_get_settings();
    $activity_enabled = ! empty( $s['activity_log_enabled'] );
    $retention_days   = absint( $s['activity_log_retention_days'] ?? 90 );
    $full_ip          = ! empty( $s['activity_log_full_ip'] );
    $export_nonce     = wp_create_nonce( 'wpmm_activity_export' );
    $export_url       = admin_url( 'admin-post.php?action=wpmm_activity_export&_wpnonce=' . $export_nonce );
    ?>
    <div class="wrap wpmm-wrap">
        <?php wpmm_page_header( WPMM_SLUG_ACTIVITY ); ?>

        <?php if ( ! $activity_enabled ) : ?>
        <div class="wpmm-card" style="max-width:640px;margin:32px auto;text-align:center;padding:48px 36px;">
            <span class="dashicons dashicons-list-view" style="font-size:48px;width:48px;height:48px;color:var(--wpmm-blue2);margin-bottom:16px;display:block;"></span>
            <h2 style="margin:0 0 12px;color:var(--wpmm-blue);">Site Activity Log is disabled</h2>
            <p style="color:var(--wpmm-text-light);margin:0 0 24px;line-height:1.6;">
                Enable the activity log to track user logins, plugin changes, and other key site events.
                IP addresses are anonymised by default in accordance with GDPR requirements.
            </p>
            <a href="<?php echo esc_url( wpmm_subpage_url( WPMM_SLUG_SETTINGS ) . '#activity-log-settings' ); ?>"
               class="wpmm-btn wpmm-btn-primary">
                <span class="dashicons dashicons-admin-settings"></span>
                Enable in Settings &rarr;
            </a>
        </div>
        <?php return; endif; ?>

        <!-- Toolbar -->
        <div class="wpmm-card wpmm-activity-toolbar" style="margin-bottom:16px;">
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <select id="wpmm-activity-category" class="wpmm-input" style="width:180px;">
                    <option value="">All Categories</option>
                    <option value="authentication">Authentication</option>
                    <option value="user_management">User Management</option>
                    <option value="site_change">Site Changes</option>
                </select>
                <input type="text" id="wpmm-activity-search" class="wpmm-input" style="width:220px;"
                       placeholder="Search events, users, IPs&hellip;">
                <input type="date" id="wpmm-activity-from" class="wpmm-input" style="width:145px;" title="From date">
                <span style="color:var(--wpmm-gray);">to</span>
                <input type="date" id="wpmm-activity-to" class="wpmm-input" style="width:145px;" title="To date">
                <button type="button" id="wpmm-activity-filter-btn" class="wpmm-btn wpmm-btn-secondary wpmm-btn-sm">
                    <span class="dashicons dashicons-filter"></span> Filter
                </button>
                <button type="button" id="wpmm-activity-reset-btn" class="wpmm-btn wpmm-btn-secondary wpmm-btn-sm">Reset</button>
                <div style="margin-left:auto;display:flex;gap:8px;">
                    <button type="button" id="wpmm-activity-export-btn"
                            class="wpmm-btn wpmm-btn-secondary wpmm-btn-sm"
                            data-nonce="<?php echo esc_attr( wp_create_nonce( 'wpmm_nonce' ) ); ?>">
                        <span class="dashicons dashicons-download"></span> Export CSV
                    </button>
                    <button type="button" id="wpmm-activity-clear-btn"
                            class="wpmm-btn wpmm-btn-secondary wpmm-btn-sm"
                            style="color:var(--wpmm-red);border-color:#fca5a5;">
                        <span class="dashicons dashicons-trash"></span> Clear Log
                    </button>
                </div>
            </div>
            <div style="margin-top:12px;display:flex;align-items:center;gap:10px;">
                <label style="font-size:13px;color:var(--wpmm-text-light);">Show:</label>
                <select id="wpmm-activity-per-page" class="wpmm-input" style="width:80px;">
                    <option value="25">25</option>
                    <option value="50" selected>50</option>
                    <option value="100">100</option>
                </select>
                <span style="font-size:13px;color:var(--wpmm-text-light);">entries per page</span>
                <span id="wpmm-activity-count" style="margin-left:auto;font-size:13px;color:var(--wpmm-gray);"></span>
            </div>
        </div>

        <!-- GDPR notice -->
        <div style="background:#eff6ff;border-left:3px solid var(--wpmm-blue2);
             padding:10px 16px;margin-bottom:16px;font-size:13px;color:#1e40af;
             border-radius:4px;display:flex;align-items:center;gap:8px;">
            <span class="dashicons dashicons-shield"></span>
            <span>
                <strong>GDPR:</strong>
                IP addresses are <?php echo $full_ip
                    ? '<strong>stored in full</strong> (full IP storage enabled in Settings)'
                    : 'anonymised (last octet masked)'; ?>.
                Auto-purge after
                <strong><?php echo $retention_days > 0 ? esc_html( $retention_days ) . ' days' : 'never (disabled)'; ?></strong>.
                <a href="<?php echo esc_url( $export_url ); ?>" style="margin-left:8px;">
                    Download data export &rarr;
                </a>
            </span>
        </div>

        <!-- Results table -->
        <div class="wpmm-card" id="wpmm-activity-table-wrap">
            <div id="wpmm-activity-loading" style="text-align:center;padding:40px;color:var(--wpmm-gray);">
                <span class="dashicons dashicons-update wpmm-spin" style="font-size:24px;width:24px;height:24px;"></span>
                <p>Loading activity log&hellip;</p>
            </div>
            <div id="wpmm-activity-table-container" style="display:none;overflow-x:auto;">
                <table class="wpmm-table" style="width:100%;">
                    <thead>
                        <tr>
                            <th style="width:36px;"><input type="checkbox" id="wpmm-activity-select-all" title="Select all"></th>
                            <th style="width:145px;">Date / Time</th>
                            <th style="width:130px;">Category</th>
                            <th>Event</th>
                            <th style="width:130px;">User</th>
                            <th style="width:120px;">IP Address</th>
                        </tr>
                    </thead>
                    <tbody id="wpmm-activity-tbody"></tbody>
                </table>
                <div id="wpmm-activity-bulk-bar"
                     style="display:none;padding:10px 0;border-top:1px solid var(--wpmm-border);
                            margin-top:8px;align-items:center;gap:10px;">
                    <button type="button" id="wpmm-activity-bulk-delete"
                            class="wpmm-btn wpmm-btn-secondary wpmm-btn-sm"
                            style="color:var(--wpmm-red);border-color:#fca5a5;">
                        <span class="dashicons dashicons-trash"></span> Delete Selected
                    </button>
                    <span id="wpmm-activity-bulk-msg" style="font-size:13px;"></span>
                </div>
            </div>
            <div id="wpmm-activity-empty" style="display:none;text-align:center;padding:40px;color:var(--wpmm-gray);">
                <span class="dashicons dashicons-list-view" style="font-size:32px;width:32px;height:32px;"></span>
                <p>No activity log entries found.</p>
            </div>
        </div>

        <!-- Pagination -->
        <div id="wpmm-activity-pagination"
             style="display:flex;align-items:center;justify-content:space-between;
                    margin-top:12px;flex-wrap:wrap;gap:8px;"></div>

        <!-- Detail drawer -->
        <div id="wpmm-activity-drawer"
             style="display:none;position:fixed;right:0;top:32px;bottom:0;width:380px;
                    background:#fff;box-shadow:-4px 0 24px rgba(0,0,0,.15);
                    z-index:99999;padding:28px;overflow-y:auto;">
            <button type="button" id="wpmm-activity-drawer-close"
                    style="position:absolute;top:16px;right:16px;background:none;
                           border:none;cursor:pointer;font-size:22px;color:var(--wpmm-gray);
                           line-height:1;">&times;</button>
            <h3 style="margin:0 0 20px;font-size:16px;color:var(--wpmm-blue);">Event Detail</h3>
            <div id="wpmm-activity-drawer-content"></div>
        </div>
        <div id="wpmm-activity-drawer-overlay"
             style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.25);z-index:99998;"></div>

    </div>
    <?php
}

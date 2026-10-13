<?php
/**
 * Greenskeeper — SMTP / Email Mailer
 *
 * Greenskeeper is always the sender of record for its own emails.
 * The phpmailer_init hook fires ONLY when Greenskeeper itself calls
 * wp_mail() — identified by the $GLOBALS['wpmm_sending'] flag set
 * around every outbound call. All other site email (WooCommerce,
 * contact forms, etc.) is never touched.
 *
 * When another SMTP plugin is detected and the admin has checked
 * "Use [plugin] instead", the flag causes Greenskeeper to stand down
 * and let the detected plugin handle delivery. The admin accepts the
 * risk that a failure in that plugin won't appear in Greenskeeper's log.
 *
 * Supported mailers:
 *  default   — WordPress default (PHP mail()), no changes made.
 *  smtp      — Manual SMTP: any host, port, username, password, encryption.
 *  sendgrid  — SendGrid API (SMTP relay, smtp.sendgrid.net:587).
 *  mailgun   — Mailgun SMTP relay (smtp.mailgun.org:587).
 *  brevo     — Brevo (Sendinblue) SMTP (smtp-relay.brevo.com:587).
 *  sendlayer — SendLayer SMTP (smtp.sendlayer.net:587).
 *  smtpcom   — SMTP.com SMTP relay (send.smtp.com:587).
 *  gmail     — Gmail / Google Workspace (smtp.gmail.com:587, App Password).
 *  microsoft — Microsoft 365 / Outlook (smtp.office365.com:587).
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

// ── SMTP plugin detection ─────────────────────────────────────────────────────

/**
 * Detect whether another SMTP plugin is active on this site.
 *
 * Returns an array [ 'slug' => '...', 'name' => '...' ] if found,
 * or false if no competing SMTP plugin is active.
 *
 * @return array|false
 */
function wpmm_detect_smtp_plugin() {
    // Map of plugin file → display name.
    // Covers all major SMTP plugins by active-install count as of 2026.
    $known = [
        'wp-mail-smtp/wp_mail_smtp.php'           => 'WP Mail SMTP',
        'fluent-smtp/fluent-smtp.php'             => 'FluentSMTP',
        'post-smtp/postman-smtp.php'              => 'Post SMTP',
        'postman-smtp/postman-smtp.php'           => 'Postman SMTP',
        'easy-wp-smtp/easy-wp-smtp.php'           => 'Easy WP SMTP',
        'mailin/sendinblue.php'                   => 'Brevo (Sendinblue)',
        'gravity-smtp/gravity-smtp.php'           => 'Gravity SMTP',
        'wp-offload-ses-lite/wp-offload-ses-lite.php' => 'WP Offload SES',
        'gmail-smtp/main.php'                     => 'Gmail SMTP',
    ];

    if ( ! function_exists( 'is_plugin_active' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    foreach ( $known as $slug => $name ) {
        if ( is_plugin_active( $slug ) ) {
            return [ 'slug' => $slug, 'name' => $name ];
        }
    }

    // Also check network-activated plugins on multisite.
    if ( is_multisite() ) {
        $network_active = get_site_option( 'active_sitewide_plugins', [] );
        foreach ( $known as $slug => $name ) {
            if ( isset( $network_active[ $slug ] ) ) {
                return [ 'slug' => $slug, 'name' => $name ];
            }
        }
    }

    return false;
}

// ── Apply mailer config — Greenskeeper emails only ────────────────────────────
//
// This hook fires for EVERY wp_mail() call on the site, but we immediately
// return if $GLOBALS['wpmm_sending'] is not true — meaning Greenskeeper
// did not initiate this email. This guarantees we never interfere with
// WooCommerce, contact forms, password resets, or any other plugin's mail.
add_action( 'phpmailer_init', 'wpmm_configure_phpmailer' );

function wpmm_configure_phpmailer( $phpmailer ) {
    // Only act on Greenskeeper-initiated emails.
    if ( empty( $GLOBALS['wpmm_sending'] ) ) {
        return;
    }

    $s = wpmm_get_settings();

    // If the admin has opted to defer to a detected SMTP plugin, stand down.
    $detected = wpmm_detect_smtp_plugin();
    if ( $detected && ! empty( $s['smtp_defer_to_plugin'] ) ) {
        return;
    }

    $mailer = $s['smtp_mailer'] ?? 'default';

    if ( $mailer === 'default' ) {
        return; // WordPress default — no changes.
    }

    // Pre-configured provider SMTP settings.
    $provider_map = [
        'sendgrid'  => [ 'host' => 'smtp.sendgrid.net',    'port' => 587, 'enc' => 'tls', 'user' => 'apikey' ],
        'mailgun'   => [ 'host' => 'smtp.mailgun.org',      'port' => 587, 'enc' => 'tls', 'user' => '' ],
        'brevo'     => [ 'host' => 'smtp-relay.brevo.com',  'port' => 587, 'enc' => 'tls', 'user' => '' ],
        'sendlayer' => [ 'host' => 'smtp.sendlayer.net',    'port' => 587, 'enc' => 'tls', 'user' => '' ],
        'smtpcom'   => [ 'host' => 'send.smtp.com',         'port' => 587, 'enc' => 'tls', 'user' => '' ],
        'gmail'     => [ 'host' => 'smtp.gmail.com',        'port' => 587, 'enc' => 'tls', 'user' => '' ],
        'microsoft' => [ 'host' => 'smtp.office365.com',    'port' => 587, 'enc' => 'tls', 'user' => '' ],
    ];

    if ( isset( $provider_map[ $mailer ] ) ) {
        $p         = $provider_map[ $mailer ];
        $host      = $p['host'];
        $port      = $p['port'];
        $enc       = $p['enc'];
        $smtp_user = $p['user'] ?: ( $s['smtp_username'] ?? '' );
        $smtp_pass = wpmm_decrypt_smtp( $s['smtp_password_enc'] ?? '' );
    } else {
        // Manual SMTP.
        $host      = $s['smtp_host']     ?? '';
        $port      = (int) ( $s['smtp_port'] ?? 587 );
        $enc       = $s['smtp_enc']      ?? 'tls';
        $smtp_user = $s['smtp_username'] ?? '';
        $smtp_pass = wpmm_decrypt_smtp( $s['smtp_password_enc'] ?? '' );
    }

    if ( ! $host ) {
        return; // Not configured — fall back to WordPress default.
    }

    $phpmailer->isSMTP();
    $phpmailer->Host       = $host;
    $phpmailer->Port       = $port;
    $phpmailer->SMTPAuth   = ( $smtp_user !== '' );
    $phpmailer->Username   = $smtp_user;
    $phpmailer->Password   = $smtp_pass;
    $phpmailer->SMTPSecure = ( $enc === 'tls' )
        ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS
        : ( $enc === 'ssl' ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS : '' );

    $from_name  = ! empty( $s['smtp_from_name'] )  ? $s['smtp_from_name']
               : ( ! empty( $s['company_name'] )   ? $s['company_name']
               :   get_bloginfo( 'name' ) );
    $from_email = ! empty( $s['smtp_from_email'] )
        ? sanitize_email( $s['smtp_from_email'] )
        : $phpmailer->From;

    $phpmailer->From     = $from_email;
    $phpmailer->FromName = $from_name;
}

/**
 * Wrap a wp_mail() call with the wpmm_sending flag so Greenskeeper's
 * phpmailer_init hook knows to apply its SMTP settings.
 *
 * Use this instead of wp_mail() everywhere inside Greenskeeper.
 *
 * @param string       $to
 * @param string       $subject
 * @param string       $message
 * @param array|string $headers
 * @param array        $attachments
 * @return bool
 */
function wpmm_wp_mail( $to, $subject, $message, $headers = [], $attachments = [] ) {
    $GLOBALS['wpmm_sending'] = true;
    $result = wp_mail( $to, $subject, $message, $headers, $attachments );
    $GLOBALS['wpmm_sending'] = false;
    return $result;
}

// ── AJAX: save SMTP settings ──────────────────────────────────────────────────
add_action( 'wp_ajax_wpmm_save_smtp', 'wpmm_ajax_save_smtp' );

function wpmm_ajax_save_smtp() {
    check_ajax_referer( 'wpmm_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Permission denied.' );
    }

    $s = wpmm_get_settings();

    $s['smtp_mailer']        = sanitize_text_field( wp_unslash( $_POST['smtp_mailer']     ?? 'default' ) );
    $s['smtp_host']          = sanitize_text_field( wp_unslash( $_POST['smtp_host']       ?? '' ) );
    $s['smtp_port']          = absint( $_POST['smtp_port']                    ?? 587 );
    $raw_enc                 = sanitize_text_field( wp_unslash( $_POST['smtp_enc']         ?? '' ) );
    $s['smtp_enc']           = in_array( $raw_enc, [ 'tls', 'ssl', 'none' ], true ) ? $raw_enc : 'tls';
    $s['smtp_username']      = sanitize_text_field( wp_unslash( $_POST['smtp_username']   ?? '' ) );
    $s['smtp_from_email']    = sanitize_email(      wp_unslash( $_POST['smtp_from_email'] ?? '' ) );
    $s['smtp_from_name']     = sanitize_text_field( wp_unslash( $_POST['smtp_from_name']  ?? '' ) );
    $s['smtp_defer_to_plugin'] = ! empty( $_POST['smtp_defer_to_plugin'] ) ? 1 : 0;

    $raw_pass = sanitize_text_field( wp_unslash( $_POST['smtp_password'] ?? '' ) );
    if ( $raw_pass !== '' && $raw_pass !== '••••••••' ) {
        $s['smtp_password_enc'] = wpmm_encrypt_smtp( $raw_pass );
    }

    wpmm_save_settings( $s );
    wp_send_json_success( [ 'mailer' => $s['smtp_mailer'] ] );
}

// ── AJAX: send a test email ───────────────────────────────────────────────────
add_action( 'wp_ajax_wpmm_test_smtp', 'wpmm_ajax_test_smtp' );

function wpmm_ajax_test_smtp() {
    check_ajax_referer( 'wpmm_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Permission denied.' );
    }

    $to      = sanitize_email( wp_unslash( $_POST['test_email'] ?? '' ) );
    $current = wp_get_current_user();
    if ( ! $to ) {
        $to = $current->user_email;
    }
    if ( ! is_email( $to ) ) {
        wp_send_json_error( 'Invalid test email address.' );
    }

    $site    = get_bloginfo( 'name' );
    $subject = '[' . $site . '] Greenskeeper — SMTP Test';
    $body    = '<p>This is a test email sent from <strong>' . esc_html( $site ) . '</strong> '
             . 'via Greenskeeper&rsquo;s SMTP configuration.</p>'
             . '<p>If you received this, your SMTP settings are working correctly.</p>';

    $headers = [ 'Content-Type: text/html; charset=UTF-8' ];

    add_action( 'wp_mail_failed', 'wpmm_capture_mail_error' );
    $GLOBALS['wpmm_mail_error'] = '';

    $sent = wpmm_wp_mail( $to, $subject, $body, $headers );

    remove_action( 'wp_mail_failed', 'wpmm_capture_mail_error' );

    if ( $sent ) {
        wp_send_json_success( 'Test email sent successfully to ' . $to . '.' );
    } else {
        $err = $GLOBALS['wpmm_mail_error'] ?: 'wp_mail() returned false. Check your SMTP credentials.';
        wp_send_json_error( $err );
    }
}

function wpmm_capture_mail_error( $wp_error ) {
    $GLOBALS['wpmm_mail_error'] = $wp_error->get_error_message();
}

// ── Encryption helpers ────────────────────────────────────────────────────────
function wpmm_encrypt_smtp( $plaintext ) {
    if ( $plaintext === '' || ! function_exists( 'openssl_encrypt' ) ) {
        return base64_encode( $plaintext ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
    }
    $key    = hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY, true );
    $iv     = openssl_random_pseudo_bytes( 16 );
    $cipher = openssl_encrypt( $plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );
    return base64_encode( $iv . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
}

function wpmm_decrypt_smtp( $stored ) {
    if ( $stored === '' ) { return ''; }
    if ( ! function_exists( 'openssl_decrypt' ) ) {
        return base64_decode( $stored ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
    }
    $data = base64_decode( $stored ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
    if ( strlen( $data ) <= 16 ) {
        return base64_decode( $stored ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
    }
    $key = hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY, true );
    $iv  = substr( $data, 0, 16 );
    $enc = substr( $data, 16 );
    $dec = openssl_decrypt( $enc, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );
    return $dec !== false ? $dec : '';
}


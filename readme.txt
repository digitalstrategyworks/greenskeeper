=== Greenskeeper ===
Contributors:      tonyzeoli
Author:            Tony Zeoli
Author URI:        https://digitalstrategyworks.com
Tags:              maintenance, updates, smtp, email, multisite
Requires at least: 5.8
Tested up to:      7.0
Requires PHP:      8.0
Stable tag:        2.2.4
License:           GPL-2.0+
License URI:       https://www.gnu.org/licenses/gpl-2.0.html
Copyright:         2026 Digital Strategy Works LLC

Manage WordPress updates, filter comment spam, send branded email reports, and configure SMTP delivery — for single sites and Multisite networks.

== Description ==

Greenskeeper is a professional WordPress maintenance plugin for developers and agencies. It centralises update management for WordPress Core, plugins, and themes, pairs it with a polished email reporting workflow, and adds layered comment spam protection — all from a single purpose-built admin dashboard.

**Updates & Reporting:**

* Scans for available WordPress Core, plugin, and theme updates in separate sections
* Updates items individually or in batch with a real-time progress bar and plain-English error explanations
* Logs every update action automatically — searchable by item name or date range, grouped into sessions
* Builds a branded HTML maintenance report email from each update session and sends it to your client
* Report emails support Update Notes (admin note to recipient) and Additional Manual Updates (for licensed plugins updated outside the plugin)
* Configures reliable SMTP email delivery via nine supported providers — no separate SMTP plugin required
* Manages agency branding: company logo, company name, and default administrator shown on reports
* Works on single-site WordPress installs and Multisite networks
* Multisite: Site Scope Selector on Updates, Spam Log, and Settings — view and manage any single site or the full network from Network Admin

**Spam Filter & Comments:**

* Layer 1 — Local filtering (always active): honeypot hidden field, submission time check, link count limit, keyword blocklist, IP blocklist, duplicate comment detection
* Layer 2 — Akismet cloud filtering (optional): enter your Akismet API key to enable AI-powered spam detection. Automatically skipped when the standalone Akismet plugin is active
* Spam Log page: review every blocked comment attempt — filter by rule or IP, add offending IPs to the blocklist with one click, and bulk-delete entries
* Disable Comments: remove comment support from all post types and hide the Comments admin menu site-wide

**Important — Akismet licensing:** Akismet is free for personal, non-commercial sites only. Any commercial or client site requires a paid Akismet plan available at [akismet.com/plans](https://akismet.com/plans/). Greenskeeper provides the integration; you are responsible for having a valid Akismet licence appropriate for your site's use.

**Supported SMTP Providers:**

SendGrid, Mailgun, Brevo, SendLayer, SMTP.com, Gmail / Google Workspace, Microsoft / Outlook / Office 365, manual SMTP, or WordPress default.

**Who it is for:**

Web developers, digital agencies, and WordPress administrators who manage client sites and need a reliable, repeatable maintenance and security workflow with professional client-facing reporting. Named after the greenskeeper who maintains the golf course — meticulous, professional, invisible.

== Installation ==

= Single-Site Install =

1. In your WordPress admin go to **Plugins → Add New → Upload Plugin**.
2. Upload `greenskeeper.zip` and click **Install Now**.
3. Click **Activate Plugin**.
4. Navigate to **Site Maintenance** in the left-hand admin menu.
5. Open **Settings** and configure your company branding, client email, default administrator, SMTP delivery, and spam filtering.

= Multisite / Network Install =

1. Log in as a Super Admin and go to **Network Admin → Plugins → Add New → Upload Plugin**.
2. Upload `greenskeeper.zip` and click **Install Now**.
3. Click **Network Activate** to activate across all sites simultaneously, **or** activate per-site from each site's own Plugins screen.
4. Navigate to **Site Maintenance** in the Network Admin menu or any site's admin menu.
5. Each site has its own independent Settings, Update Log, and Email Log.

= Manual Install =

1. Unzip the archive and upload the `greenskeeper` folder to `/wp-content/plugins/`.
2. Activate from the WordPress Plugins screen.

---

== Using the Plugin ==

= Running Updates =

1. Go to **Site Maintenance → Updates**.
2. The page loads and automatically scans for available updates.
3. The **Performing Administrator** dropdown at the top defaults to your saved default admin (set in Settings). Override it here for this session only.
4. Check the items you want to update — or use **Select All** per section.
5. Click **Update Selected**. Each item updates sequentially with inline feedback.
6. When all items are done, the global success banner appears with a link to **Send Report Email**.

= Sending a Report Email =

1. After running updates, go to **Site Maintenance → Email Reports**.
2. The plugin automatically selects the session you just ran — you will see "Updates from session on [date]" in the Email Template section.
3. Confirm the recipient email (pre-filled from Settings) and edit the subject line if needed.
4. Click **Send Report Email**.
5. The sent email appears in the **Sent Email History** table below.

= Using the Spam Log =

1. Go to **Site Maintenance → Spam Log**.
2. The stats card at the top shows how many attempts each rule has blocked since activation.
3. The table lists every blocked attempt with date, rule, IP address, author details, and a content preview.
4. Click **Block IP** next to any row to add that IP to the blocklist in Settings immediately.
5. Use the **Rule** and **IP** filters to narrow the list. Click **Apply** to filter; **×&nbsp;Clear** to reset.
6. Check individual rows and click **Delete Selected** to remove entries, or **Clear All** to wipe the entire log.

= Previewing a Sent Email =

Click the eye icon in the Sent Email History table. The email renders in a full modal preview using the current template. Even old emails show current branding because the preview always rebuilds the body from the original log entries.

= Resending an Email =

Click **Resend** in the Sent Email History table. The email is rebuilt from the original session entries and sent again to the same recipient.

---

== External Services ==

This plugin connects to one external service: the Akismet API. All other
functionality runs entirely on your own server with no external connections.

= Akismet Spam Filtering (optional) =

**What it is:** Akismet is a cloud-based spam detection service operated by
Automattic, Inc. Greenskeeper includes an optional integration that allows you
to submit comment data to Akismet's API for spam classification.

**This feature is entirely opt-in.** Akismet is only activated if you enter an
Akismet API key in Greenskeeper → Settings → Spam Filter & Comments. If no key
is entered, no data is ever sent to Akismet.

**What data is sent and when:** When Akismet is enabled and a comment is
submitted on your site, Greenskeeper sends the following data to Akismet's API:

* Your site URL
* The commenter's IP address
* The commenter's browser user agent string
* The HTTP referrer header from the comment request
* The URL of the page the comment was submitted on
* The comment type, author name, author email, author URL, and comment content

This data is sent each time a new comment is submitted and passes Greenskeeper's
local filters. If Akismet is unreachable, Greenskeeper fails open (allows the
comment through) rather than blocking it.

Additionally, when you click "Verify & Save Key" in Settings, your Akismet API
key and your site URL are sent to Akismet's verification endpoint to confirm the
key is valid.

**Akismet's terms of service and privacy policy:**

* Terms of service: https://akismet.com/tos/
* Privacy policy: https://automattic.com/privacy/

**Important licensing note:** Akismet's free plan is for personal,
non-commercial sites only. Any commercial or client site requires a paid
Akismet plan. See https://akismet.com/plans/ for details. Greenskeeper provides
the integration; you are responsible for holding a valid Akismet licence
appropriate for your site's use.

== Frequently Asked Questions ==

= Does Greenskeeper conflict with WP Mail SMTP or other SMTP plugins? =
No — from v2.2.1 onward, Greenskeeper is always the sender of record
for its own emails by default. It applies its SMTP configuration only
to emails it initiates (maintenance reports, admin notifications, test
emails) and never interferes with WooCommerce, contact forms, password
resets, or any other plugin's mail. When Greenskeeper detects another
SMTP plugin on the site, it shows an informational notice on the SMTP
settings card naming the plugin and confirming Greenskeeper is operating
independently. If you prefer to hand delivery to the detected plugin,
a checkbox on the settings card lets you do that — with a clear warning
that a failure in that plugin may prevent Greenskeeper reports from
sending and will not appear in Greenskeeper's email log.

= Which SMTP plugins does Greenskeeper detect? =
Greenskeeper detects the following SMTP plugins: WP Mail SMTP,
FluentSMTP, Post SMTP, Postman SMTP, Easy WP SMTP, Brevo (Sendinblue),
Gravity SMTP, WP Offload SES, and Gmail SMTP. Detection covers both
site-activated and network-activated installations on multisite.


= Does Greenskeeper include a System Info report? =
Yes — from v2.1.11 onward, Greenskeeper includes a System Info page
(Greenskeeper → System Info in the WordPress admin sidebar). It displays
your full server environment (PHP version, extensions, server software),
WordPress environment (version, URLs, memory limit, debug mode, database),
active theme, and a complete list of active plugins with versions and authors.
A sticky copy-and-paste panel lets you copy the full report as plain text
to include in support tickets to plugin or theme developers.


= Does Greenskeeper send notifications to the administrator after updates? =
Yes — from v2.1.10 onward, Greenskeeper can send an internal notification
email to the performing administrator when a batch of updates completes.
Three notification types are available, each independently toggleable in
Greenskeeper → Settings → Email Notifications: (1) All updates succeeded
(off by default — routine clean batches don't need an email), (2) Some
updates failed (on by default — partial failures need attention), (3) All
updates failed (on by default — complete failures require immediate action).
These notifications go only to the administrator, not to the client.

= What happens when some updates fail and others succeed? =
The Updates page now shows one of three distinct states after a batch
completes: (A) All succeeded — green confirmation with a Send Report link;
(B) Partial success — amber warning showing how many succeeded and how many
failed, with options to retry the failed updates or send a report with only
the successful ones; (C) All failed — red warning with a Retry All option.
The Send Report link is never shown when all updates failed since there is
nothing to report.

= If I retry a failed update and it succeeds, does the failure still appear? =
No. If a plugin update fails and you retry it in the same session and the
retry succeeds, the failed row is suppressed from both the Update Log display
and the email report. Only the successful outcome is shown. The failed row
remains in the database for audit purposes but is hidden from the user-facing
views. This applies to both individual retries and batch retries.


= Does Greenskeeper log site activity and user logins? =
Yes — Greenskeeper includes a Site Activity Log that records user logins,
failed login attempts, plugin changes, theme switches, user account changes,
and WordPress core updates. The log is disabled by default and can be enabled
in Greenskeeper → Settings → Site Activity Log.

= Is the Site Activity Log GDPR compliant? =
Yes. The activity log is designed with GDPR data minimisation principles from
the ground up. IP addresses are anonymised by default — the last octet of IPv4
addresses and the last 80 bits of IPv6 addresses are zeroed before storage,
following the approach recommended by the European Data Protection Board. Log
entries are automatically purged after a configurable retention period (default
90 days). You can export all stored activity data as CSV to respond to Subject
Access Requests, and bulk-delete all entries at any time from the Site Activity
page. Full IP address storage is available as an explicit opt-in for sites with
a documented legitimate purpose under GDPR Article 6.

= What events does the Site Activity Log record? =
Authentication: user logins, failed login attempts, logouts, password reset
requests, password changes. User management: account creation and deletion,
role changes, administrator profile updates. Site changes: plugin activation,
deactivation and deletion, theme switches, WordPress core updates, and changes
to key WordPress options (site title, admin email, permalink structure, etc.).
Post and page editing activity is reserved for a future Pro version.

= How long does Greenskeeper keep activity log data? =
By default, log entries are automatically purged after 90 days via a daily
WordPress cron event. You can change the retention period in Greenskeeper →
Settings → Site Activity Log. Set the retention to 0 to keep entries
indefinitely (not recommended for GDPR compliance). Entries can also be
manually deleted individually or in bulk from the Site Activity page at
any time.

= Can I export the activity log for a GDPR Subject Access Request? =
Yes. The Site Activity page includes an Export CSV button that downloads all
stored activity log entries as a UTF-8 CSV file. You can also access the
export via Greenskeeper → Settings → Site Activity Log. The export includes
all logged fields: event type, category, summary, context, user ID, username,
display name, anonymised IP address, and timestamp.



= Does Greenskeeper report updates made outside the plugin? =

Yes, from version 1.9.1. Greenskeeper hooks into WordPress's
upgrader_process_complete action, which fires for any update that runs
through WordPress's standard Plugin_Upgrader or Theme_Upgrader — including
updates made from the WordPress Updates screen, the Avada plugins dashboard
(for Avada Core and Avada Builder), or any other standard WordPress update
mechanism.

These external updates are logged automatically with a session labelled
"External" in the Update Log, and are included as a separate "Updates Made
Outside Greenskeeper" section in the next maintenance report email.

= How does Greenskeeper handle Avada theme updates? =

Greenskeeper handles Avada-related updates in two ways depending on the
update type:

**Avada theme, Avada Core, and Avada Builder updates** — once your Avada
license is registered, these appear in the standard WordPress updates list
and can be updated from either the WordPress Updates screen or the Avada
plugins dashboard. Both routes fire WordPress's standard upgrade hooks.
Greenskeeper detects and logs these automatically and includes them in the
maintenance report email.

**Avada Patches** — patches applied through Avada's own Maintenance →
Plugins & Add-Ons dashboard use Avada's proprietary update mechanism and
do not fire WordPress's standard hooks. Greenskeeper cannot detect these
automatically. They should be documented manually using the Additional
Manual Updates field on the Email Reports page before sending the report.

The Updates page also shows a contextual notice when the Avada theme is
installed, explaining the required update order: Avada theme first, then
Avada Core, then Avada Builder.

= What is the difference between an external update and a manual update? =

An **external update** is one that Greenskeeper detected automatically
because it went through WordPress's standard update mechanism (Plugin_Upgrader
or Theme_Upgrader). These are logged and included in the email without
any action from you.

A **manual update** is one that Greenskeeper cannot detect — for example
an Avada Patch, a plugin updated through a vendor's own proprietary
dashboard, or an FTP file replacement. These must be documented using the
Additional Manual Updates field on the Email Reports page.

= Does the plugin support Avada theme updates? =

Yes, with important notes. Avada Core and Avada Builder appear in the standard
WordPress plugin update list once your Avada license is registered, and the plugin
can update them normally. The Updates page shows a contextual notice when Avada is
installed, explaining the required update order: Avada theme first, then Avada Core,
then Avada Builder. A confirmation prompt appears if you select the Avada theme for
update, reminding you to follow up with the companion plugins.

Avada Patches are managed separately through Avada's own dashboard (Avada →
Maintenance → Plugins & Add-Ons) and do not appear in the standard WordPress update
API, so they cannot be detected or applied from this plugin. The Updates page
includes a direct link to that dashboard so you can check after completing your
regular updates.


= Does this plugin support WordPress Multisite? =

Yes. It can be network-activated by a Super Admin to cover all sites simultaneously, or activated per-site by individual Administrators. Each site maintains its own isolated database tables, update log, and email log. The plugin handles cross-site AJAX correctly on Multisite so email sending always reads from the correct sub-site's log table.

= Why are my updates not showing in the Update Log? =

If you upgraded the plugin by uploading new files without deactivating first, the database schema may not have been upgraded. Open **Update Log**, expand the **Database Diagnostic** panel at the bottom, and click **Force DB Upgrade Now**. The panel shows both database tables with their column lists highlighted in green (present) or red (missing). After the upgrade click Refresh — all sessions should appear.

= Emails are not being delivered. What should I do? =

By default WordPress sends email via PHP's `mail()` function, which many hosting providers block or which major inboxes mark as spam. Go to **Settings → SMTP & Email Delivery** and configure a dedicated SMTP provider. Use **Send Test Email** to verify your connection before sending a real report. See the SMTP Setup Guides section below for step-by-step instructions for each supported provider.

= Why did a plugin or theme update fail? =

Premium and licensed plugins that require a valid license key for automatic updates will fail with a mapped error message. The Update Log and email reports both include a plain-English explanation and an action recommendation. These items must be updated manually through the vendor's dashboard or by providing a valid license key.

= Can I send the report email from a specific email address? =

Yes. Go to **Settings → SMTP & Email Delivery** and fill in the **From Name** and **From Email** fields. The From Email must be authorised to send from your SMTP provider or domain — using an unverified address is the most common cause of delivery failures.

= Can I update WordPress Core separately from plugins and themes? =

Yes. The Updates page has three separate sections — WordPress Core, Plugins, and Themes — each with its own Select All checkbox. You can update Core alone, plugins alone, themes alone, or any combination.

= Is my SMTP password stored securely? =

Yes. Passwords and API keys are encrypted with AES-256-CBC before being saved to the database. The encryption key is derived from your WordPress installation's AUTH_KEY and SECURE_AUTH_KEY constants, which are unique per site and defined in wp-config.php. The raw password is never output into the browser — only a masked placeholder is shown when a value is already saved.

= Where is the plugin data stored? =

Three custom database tables per site:
* `{prefix}_wpmm_update_log` — one row per update action (session_id, item_name, item_type, item_slug, old_version, new_version, status, error_code, message, updated_at)
* `{prefix}_wpmm_email_log` — one row per email send (session_id, to_email, subject, body, status, sent_at)
* `{prefix}_wpmm_spam_log` — one row per blocked comment attempt (rule, author_ip, author_name, author_email, author_url, comment_content, post_id, blocked_at)

Plugin settings (branding, SMTP, spam filter configuration, client email, default admin, API key) are stored in the `wpmm_settings` WordPress option.



= Can I review blocked spam comments? =

Yes. Go to **Site Maintenance → Spam Log**. Every comment attempt blocked by
any local filter rule (honeypot, time check, keyword, IP, link count, duplicate)
is logged there with the author's IP, name, email, and a content preview. Akismet-
blocked comments are logged here too and also appear in WordPress's native
Comments → Spam queue.

From the Spam Log you can: filter by rule or IP, add an IP to the blocklist
with one click, delete individual entries, or clear the entire log.



= Why were themes not showing in my email reports? =

This was a bug in versions prior to 1.9.1. Theme update log entries stored
with item_type as 'themes' (plural) were incorrectly bucketed into the
Plugins section. Version 1.9.1 normalises both spellings. No data was lost
— resending any previous email from the Sent Email History table will now
show themes in the correct Themes section.

= Does the email report include spam filter activity? =

Yes, from version 1.9.1. Every maintenance report email includes a Spam
Activity section listing comment attempts blocked since the last report was
sent. Each entry shows when it was blocked, which rule caught it, the
submitter's IP, and a content preview. If no spam was blocked since the
last report the section is omitted entirely.

= How does the administrator name appear in email reports? =

From version 1.9.1 the email uses the administrator's First Name and Last
Name from their WordPress user profile. Go to Users &rarr; Your Profile and
fill in the First Name and Last Name fields, then click Update Profile. If
no first or last name is saved, the Display Name is used as a fallback.

= Who can access Greenskeeper? =

By default, any WordPress Administrator can access the plugin. Once you save the
Manage Plugin Access settings (Settings → Manage Plugin Access), only the
administrators you have explicitly checked can see or use any part of the plugin.
Unchecked administrators see no menu item and cannot reach any plugin page.

Your own account is always locked in — you cannot accidentally remove your own
access from within the plugin.

= Can a client with Administrator access see the plugin? =

Not after you configure the Manage Plugin Access card. Go to
**Site Maintenance → Settings**, scroll to **Manage Plugin Access**, uncheck the
client's administrator account, and click **Save Access Settings**. That account
will no longer see the Site Maintenance menu or any plugin page.

= What if I get locked out of the plugin? =

Lockout cannot happen from within the plugin UI — your own account is always
kept in the access list automatically. If you are locked out through a direct
database change, connect to the database and either delete the `wpmm_settings`
option (which resets to the manage_options fallback) or add your user ID back
to the `access_user_ids` array in that option.

= Does the plugin support two-factor authentication? =

The plugin does not implement 2FA itself. Instead, it detects whether a 2FA plugin
is active and shows a notice on every plugin page if none is found, with direct
links to install WP 2FA or Two Factor. We recommend protecting the administrator
accounts that have wpmm_access with 2FA via one of these dedicated plugins:
WP 2FA (by Melapress), Two Factor (official WordPress.org plugin),
Wordfence Security, or iThemes Security Pro.


= How do spam filter settings work on a Multisite network? =

Each sub-site has its own independent spam filter settings stored in that
site's wpmm_settings option. From Network Admin, go to
Settings → Spam Filter & Comments. The All Sites view shows a summary table
of every site with its spam status, Akismet connection, and comments status.
Select a specific site from the Site Scope Bar to edit its settings. Changes
only affect that site and are saved immediately.

= Can I run updates for all sites at once, or only one site at a time? =

Both. In Network Admin, the Site Scope Bar on the Updates page defaults to
All Sites, which shows all available updates for all installed plugins and
themes. Selecting a specific site filters the list to only the plugins and
themes activated on that site, and runs updates in that site's context.

= Does the network email report cover all sites? =

Yes. When the Email Reports page is in All Sites scope (Network Admin,
no site selected), sending the report builds a consolidated email with a
section per site. Each section contains that site's own Core, Plugins, and
Themes update tables. When a single site is selected, the report covers
only that site in the standard single-site format.

= Does the spam filter work without an Akismet API key? =

Yes. The local filtering layer (honeypot field, submission time check, link count
limit, keyword blocklist, IP blocklist, and duplicate detection) runs entirely on
your server with no external API calls. Local filtering alone catches the majority
of automated bot spam. Adding an Akismet API key activates a second layer of
AI-powered cloud filtering for more comprehensive coverage.

= Do I need a paid Akismet account? =

Akismet's free plan is for personal, non-commercial sites only. Any commercial
website — including client sites managed by an agency — requires a paid Akismet
plan. Visit [akismet.com/plans](https://akismet.com/plans/) to choose the right
plan. Greenskeeper provides the Akismet integration; licensing is your
responsibility.

= Will the spam filter conflict with the standalone Akismet plugin? =

No. Greenskeeper detects when the standalone Akismet plugin is already
active and skips its own Akismet API call automatically. Only the local filtering
layer runs in that case, so you never get double-filtering. The Settings page shows
a notice when the standalone plugin is detected.

= What happens if Akismet is unreachable when a comment is submitted? =

The plugin fails open — the comment is allowed through rather than being blocked.
This prevents legitimate comments from being lost due to a temporary API outage or
network issue. Local filters still run normally regardless of Akismet availability.

= Can I disable comments completely across the entire site? =

Yes. The Disable Comments toggle in Settings → Spam Filter & Comments removes
comment support from every post type, closes all existing comments via WordPress
filter hooks, hides the Comments admin menu item, redirects direct access to the
comments admin page, and removes discussion meta boxes from the post and page
editors. This is a site-wide setting — it applies to all post types including
custom ones.

= How do I add an IP address to the blocklist after catching a spammer? =

Two ways to add an IP. From the **Spam Log** page, click the **Block IP** button on any row — the IP is added to the blocklist instantly without leaving the page. Alternatively go to **Settings → Spam Filter & Comments**, add the address to the Blocked IP Addresses textarea (one per line), and click **Save Spam Settings**.


= How does Greenskeeper handle Multisite networks? =

In Network Admin, a Site Scope Bar appears at the top of the Updates, Spam Log,
and Settings pages. You can select "All Sites" to operate across the entire
network, or choose a specific site to scope the view to that site only.

= What does "All Sites" mode do on the Updates page? =

In All Sites mode the Updates page shows every available update for every plugin
and theme installed on the network, regardless of which site has it activated.
Running updates applies them network-wide and logs results to the network admin
site's update log. The email report lists each site as a separate section with
its own Core, Plugins, and Themes tables.

= What does single-site scope do on the Updates page? =

When you select a specific site, the Updates page filters the plugin and theme
list to only show items activated on that site (including network-activated
plugins). Updates run in that site's context and log to that site's own
wpmm_update_log table. The email report uses the single-site format.

= Are spam filter settings shared across all sites in a network? =

No. Each site has its own independent spam filter settings. In Network Admin,
select a site from the scope bar on the Settings page to view and edit that
site's spam configuration. Selecting "All Sites" shows a summary table of all
sites with their spam filter status, Akismet connection status, and comments
toggle state.

= Can I use this plugin alongside WP Mail SMTP or other SMTP plugins? =

It is recommended to use either Greenskeeper's built-in SMTP configuration **or** a separate SMTP plugin — not both. Both plugins hook into `phpmailer_init` and will conflict. If you already have WP Mail SMTP, FluentSMTP, or Post SMTP installed and configured, leave Greenskeeper's SMTP setting on **WordPress Default** and let the other plugin handle delivery.

---

== SMTP Setup Guides ==

Greenskeeper includes a built-in SMTP configuration panel that reconfigures WordPress's email delivery without requiring a separate plugin. The following guides walk through setting up each supported provider.

Go to **Settings → SMTP & Email Delivery**, click your provider's tile, and enter the credentials described below.

---

= WordPress Default =

No configuration needed. WordPress sends email via PHP's built-in `mail()` function. This is unreliable on most shared hosting — emails are frequently blocked by spam filters or rejected by recipients' mail servers. Recommended only as a fallback.

---

= SMTP (Manual) =

Use this option with any SMTP server not listed as a named provider — for example your hosting provider's mail server or a self-hosted mail server.

**Fields:**
* **SMTP Host** — the address of your mail server (e.g. `mail.yourdomain.com`)
* **Port & Encryption** — port `587` with TLS is recommended for most servers; port `465` with SSL is also common; port `25` with no encryption should only be used on internal networks
* **Username** — your SMTP account login (usually your email address)
* **Password** — your SMTP account password
* **From Name** — the display name on outgoing emails
* **From Email** — must be authorised to send from your SMTP server

---

= SendGrid =

**Free plan:** 100 emails per day. No credit card required.

**Setup steps:**
1. Create a free account at [sendgrid.com](https://sendgrid.com).
2. Complete the Sender Identity verification (domain authentication or single sender).
3. Go to **Settings → API Keys → Create API Key**.
4. Choose **Restricted Access** and enable **Mail Send → Full Access**.
5. Copy the API key (it is only shown once).
6. In Greenskeeper Settings: select **SendGrid**, enter `apikey` (literally, that exact text) as the **Username**, and paste the API key as the **Password**.
7. Set your verified sender address as the **From Email**.

**Server details (pre-configured):** `smtp.sendgrid.net` — port `587` — TLS

---

= Mailgun =

**Free tier:** 5,000 emails per month for the first 3 months, then pay-as-you-go.

**Setup steps:**
1. Create an account at [mailgun.com](https://mailgun.com).
2. Add and verify your sending domain under **Sending → Domains**.
3. Go to **Sending → Domain Settings → SMTP credentials**.
4. Note your SMTP login (usually `postmaster@yourdomain.com`) and generate or copy the password.
5. In Greenskeeper Settings: select **Mailgun**, enter your SMTP login as the **Username**, and the SMTP password as the **Password**.
6. Set a verified sender address as the **From Email**.

**Server details (pre-configured):** `smtp.mailgun.org` — port `587` — TLS

*Note: Mailgun's free tier restricts sending to verified recipient addresses only. Add recipients under Sending → Overview → Authorised Recipients if you are on the free plan.*

---

= Brevo (formerly Sendinblue) =

**Free plan:** 300 emails per day, unlimited contacts.

**Setup steps:**
1. Create a free account at [brevo.com](https://brevo.com).
2. Go to your account profile (top-right) → **SMTP & API**.
3. Under the **SMTP** tab, note your **Login** (your Brevo account email) and click **Generate a new SMTP Key** to create a password.
4. In Greenskeeper Settings: select **Brevo**, enter your Brevo login email as the **Username**, and the SMTP key as the **Password**.
5. Set a sender address you have verified in Brevo as the **From Email**.

**Server details (pre-configured):** `smtp-relay.brevo.com` — port `587` — TLS

---

= SendLayer =

**Pricing:** Paid plans starting at low volume tiers; free trial available.

**Setup steps:**
1. Sign up at [sendlayer.com](https://sendlayer.com) and add your sending domain.
2. From the SendLayer dashboard, copy your **SMTP Username** and **SMTP Password**.
3. In Greenskeeper Settings: select **SendLayer**, enter those credentials, and set a verified address as the **From Email**.

**Server details (pre-configured):** `smtp.sendlayer.net` — port `587` — TLS

---

= SMTP.com =

**Free trial:** 50,000 emails.

**Setup steps:**
1. Create an account at [smtp.com](https://smtp.com).
2. Go to **Sender → SMTP credentials**.
3. Copy your **Sender Name** (this is the Username) and your **API Key** (this is the Password).
4. In Greenskeeper Settings: select **SMTP.com**, enter the Sender Name as **Username** and the API Key as **Password**.
5. Set your verified sender address as the **From Email**.

**Server details (pre-configured):** `send.smtp.com` — port `587` — TLS

---

= Gmail / Google Workspace =

**Important:** Google disabled plain password (basic auth) for SMTP in May 2022. You must use an App Password. OAuth 2.0 is not supported by this plugin.

**Personal Gmail — setup steps:**
1. Sign in to your Google Account at [myaccount.google.com](https://myaccount.google.com).
2. Go to **Security** and confirm that **2-Step Verification** is turned on. (App Passwords are not available without it.)
3. In the Security search bar, search for **App Passwords**.
4. Click **Create**, choose **Other (custom name)**, and type `WordPress` or `Greenskeeper`.
5. Google displays a 16-character code. Copy it immediately — it will not be shown again.
6. In Greenskeeper Settings: select **Gmail / Google**, enter your full Gmail address (`you@gmail.com`) as the **Username**, and paste the 16-character App Password as the **Password**.
7. Set your Gmail address as the **From Email**.

**Google Workspace (paid) — setup steps:**
The App Password method above works identically for Workspace accounts. Alternatively, your Workspace admin can configure a **SMTP relay** in the Google Admin console (Apps → Google Workspace → Gmail → SMTP relay service), which allows sending from any user in your domain without per-account App Passwords and supports higher sending volumes.

**Server details (pre-configured):** `smtp.gmail.com` — port `587` — TLS/STARTTLS

*Gmail sending limits: personal accounts are limited to approximately 500 emails per day; Google Workspace accounts to 2,000 per day.*

---

= Microsoft / Outlook =

**Important:** Microsoft deprecated basic authentication for Exchange Online in October 2022 but preserved it specifically for SMTP AUTH submissions. App Passwords are required for personal accounts; organisation accounts need SMTP AUTH enabled by an admin.

**Personal Outlook.com accounts — setup steps:**
1. Go to [account.microsoft.com/security](https://account.microsoft.com/security).
2. Under **Advanced security options**, confirm **Two-step verification** is on.
3. Click **Create a new app password**.
4. Copy the generated password.
5. In Greenskeeper Settings: select **Microsoft / Outlook**, enter your full Outlook address (`you@outlook.com` or `you@hotmail.com`) as the **Username**, and the app password as the **Password**.

**Microsoft 365 / Office 365 organisations — setup steps:**
1. A Microsoft 365 admin must enable SMTP AUTH for the sending mailbox. In the **Microsoft 365 Admin Centre** go to: **Users → Active Users → select the user → Mail tab → Manage email apps → check Authenticated SMTP**.
2. Once enabled, use the regular Microsoft 365 email address and password as the Username and Password.
3. If your organisation enforces Multi-Factor Authentication (MFA), generate an App Password from [mysignins.microsoft.com](https://mysignins.microsoft.com) → **Security info → Add method → App password**.

**Server details (pre-configured):** `smtp.office365.com` — port `587` — TLS/STARTTLS

*Note: For older personal Outlook.com accounts that do not connect on smtp.office365.com, try using the manual SMTP option with host `smtp-mail.outlook.com` on port `587`.*

---

== Screenshots ==

1. **Dashboard** — Status summary cards showing last update date, client email, default administrator, and agency branding. Quick-navigation tiles link to all pages.
2. **Updates** — Three sections (WordPress Core, Plugins, Themes) with checkboxes, version numbers, and performing administrator dropdown. Real-time progress bar with per-item status during batch updates.
3. **Update Log** — Collapsible session accordion with search autocomplete, date filtering, per-page selector, and Previous/Next pagination.
4. **Email Reports** — Send form with subject line builder, Report Week-Ending Date picker, Update Notes textarea, Additional Manual Updates repeater, and Sent Email History table with preview modal and resend.
5. **Settings — Company, Client & Administrators** (Greenskeeper) — Logo upload, company name, client email, and Site Administrators table with Gravatar and radio selection.
6. **Settings — Spam Filter & Comments** — Master spam toggle, Disable Comments toggle, local filtering configuration (min time, max links, keyword blocklist, IP blocklist), and Akismet API key field with verify/revoke.
7. **Spam Log** — All-time stats by rule, paginated blocked-attempt table with filter, Block IP and Delete per row, bulk delete, and Clear All.
8. **Settings — SMTP & Email Delivery** — Provider tile grid with context-sensitive setup instructions and Send Test Email feature.
9. **Email Preview Modal** — Full rendered HTML email preview inside the WordPress admin.
10. **Database Diagnostic** — Expandable panel showing table columns, row counts, and Force DB Upgrade button.

== Copyright ==

Greenskeeper is copyright 2026 Digital Strategy Works LLC.

**Plugin code** is licensed under the GNU General Public License v2.0 or later
(GPL-2.0+). You are free to use, modify, and redistribute the plugin code under
the terms of that licence. A copy of the GPL is included in the plugin package
and is available at https://www.gnu.org/licenses/gpl-2.0.html.

**Documentation and written content** — including but not limited to the plugin
description, installation and usage guides, SMTP setup guides, FAQs, and all
other original prose contained in readme.txt, README.md, and within the plugin's
admin interface — is the intellectual property of Digital Strategy Works LLC and
is protected by copyright. Reproduction or redistribution of the documentation
outside the terms of the GPL as it applies to software is prohibited without
prior written permission from Digital Strategy Works LLC.

Greenskeeper, the Greenskeeper logo, and the golf-flag mark are trademarks of
Digital Strategy Works LLC. Unauthorised use of the Greenskeeper name or visual
identity in a manner that implies endorsement or affiliation is prohibited.

For licensing enquiries contact: tony@digitalstrategyworks.com

== Changelog ==

= 2.2.4 =
* Fix: Email log not updating after send. The wpmm_send_email() function
  was reading session_id from wpmm_last_session which could be stale or
  mismatched. Now accepts session_id as a parameter passed directly from
  the AJAX handler — the correct session is always logged. Also added
  graceful handling for sites where the note column does not yet exist
  in wpmm_email_log (pre-v2.1.6 installs).
* Fix: JS email history row prepend failed silently when email_id was 0.
  Row ID is now sanitised to a safe DOM selector string before use, with
  a timestamp fallback ensuring the row always lands and flashes green.

= 2.2.3 =
* Feature: Persistent session queue for Email Reports. When the admin
  clicks "Send to Email Reports" on any Update Log session, the session
  is stored in a WordPress option (wpmm_queued_session) via AJAX and
  the admin is navigated to Email Reports. The queued session panel
  appears automatically regardless of how the admin arrives at the
  screen — it persists across page loads and navigation until the
  email is sent or the admin explicitly clears it.
* Feature: Clear session button on the queued session panel. A "Clear
  Session" button appears on the panel with a confirmation dialog
  warning the admin that clearing removes the queue pointer (not the
  underlying update records, which remain in the Update Log). On
  confirmation the panel fades out and the queue is cleared.
* Feature: Update Log "Send to Email Reports" button on every non-legacy
  session. Clicking queues that session persistently via AJAX (no URL
  parameters) then navigates to Email Reports where the confirmation
  panel immediately shows the session date, counts of plugins/themes/
  core updates, and failed items excluded.
* Fix: Session queue clears automatically on successful email send so
  the next batch starts fresh.

= 2.2.2 =
* Fix: Email report sent from Updates page or Update Log "Send Report"
  button could miss entries when a retry interrupted session aggregation.
  The AJAX send handler now reads ALL update_log rows for the session
  directly from the database — the same query the Update Log page uses —
  rather than relying on pending_sessions state which can be incomplete
  after retries or page navigation.
* Feature: Session confirmation panel on Email Reports page when arriving
  from the Update Log "Send Report" button. Shows the session date, count
  of plugins/themes/core updates loaded, and count of failed items excluded.
  Confirms exactly what data will be included in the email before the admin
  sends it, eliminating ambiguity about completeness.
* Fix: Admin notices from Greenskeeper and other plugins now render above
  the Greenskeeper shell rather than inside the content area. The .wpmm-wrap
  div is now closed inside wpmm_page_header() before the shell opens, so
  WordPress injects notices into the wrap (above the shell) as expected.

= 2.2.1 =
* Fix: WordPress admin notices from Greenskeeper and other plugins now
  render above the Greenskeeper UI shell rather than being injected into
  the content area. The new v2.2 shell layout caused notices to appear
  mid-page. Fixed by firing admin_notices and all_admin_notices manually
  before the shell opens, then removing the hooks to prevent duplication.
* Feature: Greenskeeper SMTP conflict resolution. Greenskeeper is now
  always the sender of record for its own emails by default. A new
  wpmm_wp_mail() wrapper function sets $GLOBALS['wpmm_sending'] = true
  around every Greenskeeper wp_mail() call so the phpmailer_init hook
  applies Greenskeeper's SMTP settings only to Greenskeeper's own email
  — never to WooCommerce orders, contact forms, or any other plugin's
  mail. When another SMTP plugin is detected (WP Mail SMTP, FluentSMTP,
  Post SMTP, Easy WP SMTP, Brevo, Gravity SMTP, WP Offload SES, Gmail
  SMTP, Postman SMTP), an informational notice appears on the SMTP
  settings card naming the detected plugin and confirming Greenskeeper
  is operating independently. A checkbox lets the admin explicitly defer
  to the detected plugin instead, with a clear warning that doing so may
  impact email log integrity if that plugin fails. The SMTP card remains
  fully visible and editable in both states.

= 2.2 =
* Feature: Vertical sidebar navigation — replaced the horizontal tab
  bar with a vertical left-sidebar navigation panel. The sidebar is
  dark navy matching the header, uses icon + label links with a blue
  left-border active indicator, and has no width constraint — all 8
  navigation items display on single lines with no wrapping. The main
  content area is now full-width with no max-width cap, giving all
  pages significantly more horizontal real estate. A new wpmm-shell /
  wpmm-body / wpmm-sidebar / wpmm-content-area CSS layout replaces the
  old wpmm-tabs horizontal nav. wpmm_page_footer() added to close the
  shell structure at the end of each page renderer.

= 2.1.11 =
* Feature: System Info page — a new dedicated admin page (Greenskeeper →
  System Info) that displays a full report of the server and WordPress
  environment for use when submitting support tickets. Includes:
  Server Environment (OS, software, PHP version with compatibility
  indicators, PHP max input vars, PHP max post size, GD/Zip/cURL/mbstring
  extension status); WordPress Environment (version, site/home URLs,
  multisite, max upload size, memory limit, permalink structure, language,
  timezone, admin email, debug mode, database version, table prefix);
  Active Theme (name, version, author, URI, child theme indicator);
  Active Plugins (name, version, author — all active plugins including
  network-activated on multisite, sorted alphabetically). A sticky
  copy-and-paste sidebar lets you copy the full system report as plain
  text to include in support tickets to plugin developers.
* Compatibility: Tested and confirmed compatible with WordPress 7.0.
  Tested up to value updated to 7.0. Requires at least and Requires PHP
  added to the plugin file header (previously only in readme.txt).

= 2.1.10.3 =
* Fix: Plugin/theme names were blank in the admin notification email.
  Batch results are now collected directly from AJAX responses as each
  update completes, not from DOM scraping after the fact.
* Compatibility: Tested and confirmed compatible with WordPress 7.0.
  Tested up to value updated. Requires at least PHP 8.0 (above the new
  WordPress 7.0 minimum of PHP 7.4). No code changes required for the
  iframed editor (Greenskeeper has no block editor integration), the
  AI Client API, Connections API, or Abilities API.

= 2.1.10.2 =
* Fix: All three batch completion banners (green/amber/red) were visible
  simultaneously on the Updates page after a batch completed. The CSS
  display:flex rule on .wpmm-notice was overriding the HTML hidden
  attribute, causing all three banners to render visible regardless of
  the batch outcome. Fixed by adding .wpmm-notice[hidden] { display:
  none !important } to admin.css so the hidden attribute always wins.

= 2.1.10.1 =
* Fix: WordPress core updates run through Greenskeeper were not appearing
  in the email report. Root cause: after a successful core update WordPress
  forces a page reload which resets the JS sessionId variable. The Email
  Reports page hidden session field was populated from wpmm_last_session
  at PHP render time, but since the page was not reloaded after the core
  update the field still referenced the previous session. Fixed by
  populating the hidden field from the most recent wpmm_pending_sessions
  entry instead of wpmm_last_session — pending sessions is updated
  server-side and survives the page reload correctly.
* Fix: WordPress core updates made outside Greenskeeper (via the standard
  WordPress Updates screen) are now captured in the Update Log. The
  external update catcher previously excluded core updates explicitly.

= 2.1.10 =
* Fix: Update Log now suppresses failed rows when a retry in the same
  session succeeded. The failed row remains in the database for audit
  purposes but is hidden from the Update Log display and excluded from
  email reports. Rule: most recent row per plugin slug wins within a
  session. Applied to both the Update Log page renderer and the email
  body builder.
* Feature: Three batch completion states on the Updates page. Previously
  a single green banner appeared after every batch regardless of outcome.
  Now: (A) all succeeded — green banner with Send Report link; (B) partial
  success — amber warning with Retry Failed and Send Partial Report options;
  (C) all failed — red warning with Retry All option. Send Report is never
  shown when all updates failed.
* Feature: Admin notification emails — Greenskeeper can now send an
  internal notification email to the performing administrator when a batch
  completes. Three notification types, each independently toggleable in
  Settings: all updates succeeded (off by default), some updates failed
  (on by default), all updates failed (on by default). The notification
  email is separate from the client-facing report and includes a summary
  of successes and failures with links to the Update Log and Email Reports.
* Feature: Email Notifications settings card in Settings — toggle each
  admin notification type on or off independently.
* Fix: WordPress core updates made outside Greenskeeper (via the standard
  WordPress Updates screen) are now captured in the Update Log and included
  in the next email report. Previously the external update catcher
  explicitly excluded core updates. The new version is read from the global
  $wp_version (already updated at hook time); the old version from the
  update_core transient's version_checked property.

= 2.1.9 =
* Feature: Resend from Update Log — each session in the Update Log now
  has a "Send Report →" button that navigates to the Email Reports page
  with that session pre-loaded. If the session was previously emailed,
  an amber notice shows when it was sent and to whom. The subject line
  is automatically prefixed with [Updated Report] and the email body
  includes a blue banner informing the recipient this is an update to
  a previously sent report, with the original send date and time.
* Fix: Manual updates on the Email Reports page are now always included
  alongside the automated session log entries when sending — previously
  adding manual entries caused only the manual entries to appear in the
  email, dropping the full automated update list.

= 2.1.8 =
* Fix: Email Reports scope selector now honored on multisite (Codex
  audit issue #3). When a specific site is selected in Network Admin,
  the Email Reports page now switches to that site's context before
  reading the recipient email, site name, site URL (for the subject
  line), pending sessions, last session, default administrator, and
  email log history.
* Fix: Scoped update filtering no longer applied in wrong blog context
  (Codex audit issue #4). A redundant second filtering pass read
  active_plugins and active theme AFTER restore_current_blog() was
  called, filtering against the main site instead of the selected site.
  Removed — the first pass already filters correctly using values
  captured while switch_to_blog() was active.
* Fix: Removed blocking wp_update_plugins() and wp_update_themes()
  calls from wpmm_get_available_updates() which is called from AJAX.
  These caused HTTP 500 on managed hosting (Kinsta, WP Engine).
* Fix: Performing administrator no longer lost on page navigation
  (Codex audit issue #5). The admin_id selected on the Updates page
  is now stored in wpmm_pending_sessions alongside the session_id.
  When the email is sent from the Email Reports page (cross-page flow),
  the stored admin_id is read from the most recent pending session
  rather than defaulting to 0. Falls back to the site default admin
  if no session admin_id is available. Previously all of these were read from the main
  site regardless of which site was selected in the scope bar.

= 2.1.7 =
* Feature: Site Activity Log — a new dedicated admin page that tracks and
  logs key site events including user logins, failed login attempts,
  logouts, password resets, user account creation and deletion, role
  changes, plugin activation/deactivation/deletion, theme switches,
  WordPress core updates, and key settings changes. Built with GDPR
  compliance as a first principle: IP addresses are anonymised by default
  (last octet of IPv4 / last 80 bits of IPv6 zeroed), a configurable
  retention period (default 90 days) auto-purges old entries via daily
  wp-cron, a full CSV data export tool supports Subject Access Requests,
  and all entries can be bulk-deleted at any time. Full IP storage is
  available as an explicit opt-in for sites with a documented legitimate
  purpose. The activity log can be enabled or disabled independently from
  a new section in Greenskeeper Settings.

= 2.1.6 =
* Feature: Administrator notes are now stored permanently with each sent
  email. Previously the note was only included in the rendered email body
  at send time — if the template changed, historical previews lost the
  note. A new 'note' column is added to wpmm_email_log (existing installs
  are upgraded automatically on first load). The raw note text is stored
  separately from the HTML body so previews always show the exact note the
  administrator typed, regardless of how the email template has evolved.
  The preview modal displays the note in a prominently styled amber block
  above the email iframe. Emails sent before v2.1.6 show no note block
  (null note value) — only emails sent from this version onward will have
  the note stored.

= 2.1.5 =
* Fix: Update Notes field content was being added below the spam section
  where it was easy to miss. Note now appears prominently at the top of the
  email body immediately below the report heading, ensuring clients always
  see administrator notes before the update tables.
* Fix: Failed update rows in the email template now use amber styling
  ("Needs Attention" with amber background) instead of large red text
  ("Update Failed" in red). License-gated plugins show a friendly
  client-facing message instead of a technical error code. DEBUG diagnostic
  strings are stripped from messages before they reach the client email.
* Fix: iThemes Security Pro, Google Site Kit, and ShortPixel Image
  Optimizer were being deactivated after updates and not restored.
  These plugins intentionally self-deactivate during their update
  process via their own upgrader_process_complete hooks, then expect
  the updater to re-activate them afterward. The previous snapshot/
  restore approach ran before these self-deactivation hooks fired and
  therefore could not catch them.
  Added a new wpmm_post_update_reactivate() hook on
  upgrader_process_complete at priority 99 — deliberately very late
  so it runs after all plugin-specific hooks. It has two jobs:
  (1) Re-activate the plugin that Greenskeeper just updated if it
  ended up inactive after its own hooks ran; (2) Restore any other
  plugin that was active before the update but is now inactive as
  collateral damage. Uses is_plugin_active_for_network() on multisite
  to correctly handle network-activated vs site-activated plugins,
  and activate_plugin($slug, '', $is_network) accordingly.

= 2.1.4 =
* Fix: PHP Warning "Undefined variable $api_key" on the Settings page.
  The variable was renamed to $api_key_set in v2.0.5 but one reference
  in the REST API endpoints section was not updated.
* Fix: Email reports only showing the most recent session when multiple
  unsent sessions exist. The pending sessions list is now always cleared
  after any successful send, regardless of whether it was triggered from
  the Updates page or the Email Reports page.
* Fix: WooCommerce and other hook-sensitive plugins (WP Rocket, Wordfence,
  Really Simple SSL) not fully restored after collateral deactivation.
  These plugins register activation hooks that are bypassed by direct
  option writes. After the option write, activate_plugin() is now called
  for any hook-sensitive plugin in the restore list to ensure their
  activation hooks fire and they are fully re-initialized.
* Fix: Sent Email History row not appearing after send when the email
  log database insert returns ID 0 (can occur on multisite when the
  email_log table is in a different blog context). A timestamp-based
  fallback row ID is now used when email_id is 0, ensuring the row
  always appears immediately in the history table.

= 2.1.3 =
* Fix: HTTP 500 errors on some multisite networks caused by the per-site
  snapshot loop introduced in v2.1.1. Both the snapshot and restore loops
  are now wrapped in try/catch blocks for graceful fallback.
* Fix: HTTP 500 caused by premium plugins with custom updater libraries
  (e.g. WP Offload Media Pro / Delicious Brains updater) throwing ValueError
  or other exceptions during Plugin_Upgrader::upgrade(). All four upgrader
  calls (plugin normal path, plugin injected-entry path, theme normal path,
  theme injected-entry path) are now wrapped in try/catch Throwable blocks.
  When a plugin's own updater throws an exception, Greenskeeper catches it
  and returns a descriptive error message rather than an HTTP 500, directing
  the user to update via Dashboard → Updates as a fallback.

= 2.1.1 =
* Fix: Plugins activated only on a specific sub-site (not network-activated)
  could still be deactivated by collateral damage during updates. Previous
  versions only snapshotted the primary site's active_plugins and the network
  active_sitewide_plugins — missing plugins like Custom Post Type UI that are
  activated per-site on individual sub-sites. The snapshot now reads
  active_plugins from every site in the network. The restore checks each
  sub-site's current active_plugins against its snapshot and re-activates
  any plugin that was deactivated as collateral damage. The updated snapshot
  is persisted back to the network transient so retries also have access to
  the corrected per-site state.

= 2.1.0 =
* Critical fix: network-activated plugins (AIOSEO, Co-Authors Plus,
  Gravity Forms, Sucuri) were still being deactivated on subdirectory
  multisite networks despite the v2.0.8 fix. Three root causes identified
  and resolved: (1) the snapshot was being taken AFTER switch_to_blog(),
  meaning it captured the sub-site plugin list rather than the main site
  network state; (2) per-blog transients (get_transient/set_transient)
  were used for the snapshot, which are stored in the current blog's
  options table and lost when blog context switches mid-request — replaced
  with network-level site transients (get_site_transient/set_site_transient);
  (3) restore_current_blog() was called after reading the post-update plugin
  state, meaning the comparison was in the wrong blog context — blog context
  is now restored before reading post-update state so both snapshot and
  post-update reads happen in the same (main site) context.

= 2.0.9 =
* Critical fix: HTTP 500 errors on managed hosting (Kinsta, WP Engine)
  during plugin and theme updates. Root cause: wp_update_plugins() and
  wp_update_themes() make loopback HTTP requests back to the WordPress.org
  API. When called from within an AJAX request, these loopback requests
  are blocked or time out on managed hosting, causing the outer AJAX
  request to return HTTP 500. All blocking wp_update_plugins/themes()
  calls during AJAX update requests have been replaced with a non-blocking
  wp-cron background event (wpmm_refresh_update_transient) that fires
  after the request completes. The upgrader proceeds with the existing
  transient URL and the next retry benefits from the refreshed URL.

= 2.0.8 =
Critical fix: network-activated plugins (Site Kit, Sucuri, Clarity) restored after collateral deactivation.
Email: multiple sessions grouped by date with clear headers.
Email history: live AJAX update after send. Unit tests added.

= 2.0.7 =
Backup warning modal before any update. Collateral deactivation restore improved with session-keyed transient.

= 2.0.6 =
Fix: collateral plugin deactivation — active plugins snapshotted before each update and restored after.

= 2.0.5 =
Security: cross-site AJAX cap bypass (#1), Akismet site scoping (#7), spam log actions (#8), REST API key hashed (#9).
Fix: All-Sites network email order (#2), dashboard date (#6), log pagination in SQL (#10), false success banner (#11).

= 2.0.4 =
Feature: email reports accumulate all unsent sessions — separate plugin/theme updates combined into one email.

= 2.0.3 =
Fix: AIOSEO Pro incorrectly flagged as manual update — scan now refreshes before deciding.

= 2.0.2 =
Fix: Divi and premium themes now update correctly — freshness check, skin error surfacing, auto-retry.

= 2.0.1 =
Fix: Jetpack copy error now reported correctly. Gravity Forms add-ons show manual update warning.

= 2.0.0 =
Premium plugin updates confirmed working. Auto-retry with fresh signed URL. AIOSEO Pro verified.

= 1.9.9 =
Diagnostic build for AIOSEO Pro null result issue.

= 1.9.8 =
Fix: AIOSEO Pro reporting "version unchanged" — auto-retry with fresh signed URL.

= 1.9.7 =
Premium plugin updates: forces fresh wp_update_plugins() when package URL is stale.

= 1.9.6 =
Critical fix: prevent premium plugin deactivation on failed updates.

= 1.9.5 =
Feature: Sent Email History updates instantly via AJAX after send.

= 1.9.4 =
Fix: batch update timeouts on shared hosting.

= 1.9.3 =
Plugin Check compliance: gmdate(), esc_sql(), prepared queries, short description length.

= 1.9.2 =
WordPress.org compliance: sanitize $_SERVER variables, External Services disclosure, inline comments.


== Upgrade Notice ==

= 1.9.1.2 =
Fixes email report footer overlapping body content. Update tables, external updates, spam activity, and admin notes now render fully above the footer. Recommended update for all users.

= 1.9.1 =
Fixes themes missing from email reports, merges Update Notes into the Send card, adds spam activity section to emails, and shows administrator full name. No database changes.

= 1.9.0 =
Plugin renamed to Greenskeeper. Adds Multisite Site Scope Selector for Updates, Spam Log, and Settings. No database changes. Internal prefixes unchanged — existing data is preserved.

= 1.9.1.2 =
Fixes email report footer overlapping body content. Update tables, external updates, spam activity, and admin notes now render fully above the footer. Recommended update for all users.

= 1.9.1 =
Fixes themes missing from email reports, merges Update Notes into the Send card, adds spam activity section to emails, and shows administrator full name. No database changes.

= 1.9.0 =
Plugin renamed to Greenskeeper. All database tables and internal prefixes unchanged — no data migration required. Adds multisite network scope selector for Updates, Spam Log, and Spam Filter settings.

= 1.8.0 =
Adds Manage Plugin Access — control which administrators can see the plugin. On first upgrade, all current administrators retain access. Uncheck client accounts in Settings → Manage Plugin Access to hide the plugin from them.

= 1.7.0 =
Adds Spam Log page with full blocked-attempt history, stats, and IP blocklist management. Creates a new wpmm_spam_log database table on upgrade.

= 1.6.0 =
Adds layered comment spam filtering with optional Akismet integration, and a Disable Comments toggle. No database changes.

= 1.5.9.1 =
Changelog-only update. No functional changes.


= 1.5.0 =
WordPress.org Plugin Check compliance fixes. No database or functional changes.


= 1.4.9 =
Plugin renamed to Greenskeeper for WordPress.org compliance. No database or functional changes.


= 1.4.8 =
Adds Avada theme detection and update order guidance. Fixes SMTP From Name using site name instead of configured value.


= 1.4.5 =
Adds Gmail and Microsoft SMTP support. No database changes.

= 1.4.4 =
Adds built-in SMTP configuration. No database changes. If you use a separate SMTP plugin, leave Greenskeeper's SMTP setting on WordPress Default.

= 1.4.3 =
Email header redesigned. Update Log gains per-page selector and Prev/Next pagination. No database changes.

= 1.4.2 =
Fixes emails showing "No update entries found" and preview modal missing plugin lists.

= 1.4.1 =
Fixes plugins/themes missing from email body. Upgrade recommended.

= 1.4.0 =
Critical database fix. After upgrading, open Update Log and click Force DB Upgrade Now in the Database Diagnostic panel. Verify all columns are highlighted green before running new updates.

= 1.3.9 =
Critical fix: Update Log now displays all sessions. Upgrade required for anyone on 1.3.8.

= 1.3.5 =
Critical fix: Settings page save buttons now work. Upgrade required for 1.3.0–1.3.4.

= 1.3.1 =
Critical fix: Email reports now include update content. Affects all installs, especially Multisite.

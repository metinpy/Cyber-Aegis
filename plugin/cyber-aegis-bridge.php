<?php
/**
 * Plugin Name: Cyber-Aegis Hardware Bridge
 * Description: REST API and live MQTT bridge for Cyber-Aegis ESP32 security terminals. Install on your WordPress site, set a device key, then configure the device with the same key and site URL.
 * Version: 1.0.1
 * Author: Cyber-Aegis
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * License: GPL v2 or later
 * Text Domain: cyber-aegis
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Cyber_Aegis_Bridge {

    private const OPT_BLACKLIST = 'cyber_aegis_blacklist';
    private const OPT_LOCKDOWN = 'cyber_aegis_lockdown';
    private const OPT_DEVICE_KEY = 'cyber_aegis_device_key';
    private const OPT_EVENTS = 'cyber_aegis_events';
    private const OPT_FAILED_LOGINS = 'cyber_aegis_failed_logins';
    private const OPT_FIM_BASELINE = 'cyber_aegis_fim_baseline';
    private const OPT_AUTH_APPROVALS = 'cyber_aegis_auth_approvals';
    private const OPT_SETTINGS = 'cyber_aegis_settings';
    private const MAX_EVENTS = 50;
    private const BF_WINDOW_SEC = 600; // 10 minutes
    private const BF_THRESHOLD = 5;     // 5 failed attempts triggers brute force alert
    private const AUTO_BAN_THRESHOLD = 10; // auto-ban after N failed attempts
    private const AUTH_APPROVAL_TTL = 120; // seconds an admin login approval stays valid

    public function __construct() {
        add_action('init', array($this, 'firewall_blacklist'));
        add_action('init', array($this, 'maybe_block_user_enum'));
        add_action('init', array($this, 'sqli_pattern_check'), 0);
        add_action('init', array($this, 'maybe_block_xmlrpc'));
        add_action('init', array($this, 'maybe_schedule_cron'));
        add_action('template_redirect', array($this, 'maybe_lockdown'), 1);
        add_action('admin_menu', array($this, 'admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin'));
        add_action('rest_api_init', array($this, 'register_rest'));

        // Event capture hooks
        add_action('wp_login_failed', array($this, 'on_login_failed'), 10, 1);
        add_action('wp_login', array($this, 'on_login_success'), 10, 2);
        add_filter('wp_authenticate_user', array($this, 'gate_admin_login'), 999, 2);
        add_action('template_redirect', array($this, 'maybe_log_traffic'), 5);
        add_action('upgrader_process_complete', array($this, 'on_upgrade'), 10, 2);

        // FIM cron handler
        add_action('cyber_aegis_fim_check', array($this, 'fim_check'));
    }

    public function maybe_schedule_cron() {
        if (!wp_next_scheduled('cyber_aegis_fim_check')) {
            wp_schedule_event(time() + 60, 'hourly', 'cyber_aegis_fim_check');
        }
    }

    private function settings() {
        $defaults = array(
            'auto_ban'          => true,
            'block_xmlrpc'      => true,
            'block_user_enum'   => true,
            'admin_2fa'         => true,
            'geo_enabled'       => true,
            'sqli_block'        => true,
        );
        return array_merge($defaults, (array) get_option(self::OPT_SETTINGS, array()));
    }

    private function get_setting($key) {
        $s = $this->settings();
        return isset($s[$key]) ? $s[$key] : null;
    }

    /** Push event into ring buffer (newest first). */
    private function push_event($event) {
        if (!is_array($event)) return;
        $event['t'] = time();
        $events = (array) get_option(self::OPT_EVENTS, array());
        array_unshift($events, $event);
        if (count($events) > self::MAX_EVENTS) {
            $events = array_slice($events, 0, self::MAX_EVENTS);
        }
        update_option(self::OPT_EVENTS, $events, false);
    }

    private function client_ip() {
        $headers = array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR');
        foreach ($headers as $h) {
            if (!empty($_SERVER[$h])) {
                $ip = trim(explode(',', (string) $_SERVER[$h])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }

    /** Lookup country via ip-api.com (free, no key, ~45 req/min). Cached 7 days. */
    private function geo_country($ip) {
        if (!$this->get_setting('geo_enabled')) return '??';
        if ($ip === '' || $ip === '0.0.0.0' || $ip === '127.0.0.1') return '??';
        // Skip private ranges
        if (preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/', $ip)) return 'LAN';

        $key = 'ca_geo_' . md5($ip);
        $cached = get_transient($key);
        if ($cached !== false) return (string) $cached;

        $resp = wp_remote_get('http://ip-api.com/json/' . rawurlencode($ip) . '?fields=countryCode', array(
            'timeout' => 4,
        ));
        if (is_wp_error($resp)) {
            set_transient($key, '??', 6 * HOUR_IN_SECONDS);
            return '??';
        }
        $body = (string) wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        $cc = (is_array($data) && !empty($data['countryCode'])) ? substr((string) $data['countryCode'], 0, 2) : '??';
        set_transient($key, $cc, 7 * DAY_IN_SECONDS);
        return $cc;
    }

    /** Auto-add IP to blacklist (without going through REST). */
    private function ban_ip_internal($ip, $reason = 'auto') {
        $blacklist = (array) get_option(self::OPT_BLACKLIST, array());
        if (in_array($ip, $blacklist, true)) return;
        $blacklist[] = $ip;
        update_option(self::OPT_BLACKLIST, array_values($blacklist), false);
        $this->push_event(array(
            'kind'   => 'ip_banned',
            'ip'     => $ip,
            'reason' => $reason,
        ));
    }

    /** ----- FIM (File Integrity Monitor) ----- */
    private function fim_files() {
        return array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . 'wp-login.php',
            ABSPATH . 'wp-load.php',
            ABSPATH . 'wp-settings.php',
            ABSPATH . 'index.php',
        );
    }

    public function fim_baseline() {
        $baseline = array();
        foreach ($this->fim_files() as $f) {
            if (file_exists($f) && is_readable($f)) {
                $baseline[$f] = @hash_file('sha256', $f);
            }
        }
        update_option(self::OPT_FIM_BASELINE, $baseline, false);
        return $baseline;
    }

    public function fim_check() {
        $baseline = (array) get_option(self::OPT_FIM_BASELINE, array());
        if (empty($baseline)) {
            $baseline = $this->fim_baseline();
            return array('status' => 'initialized', 'count' => count($baseline));
        }
        $changes = array();
        foreach ($baseline as $f => $hash) {
            if (!file_exists($f)) {
                $changes[] = array('file' => basename($f), 'reason' => 'missing');
                continue;
            }
            $current = @hash_file('sha256', $f);
            if ($current !== $hash) {
                $changes[] = array('file' => basename($f), 'reason' => 'modified');
            }
        }
        foreach ($changes as $c) {
            $this->push_event(array(
                'kind'   => 'fim_alert',
                'file'   => $c['file'],
                'reason' => $c['reason'],
            ));
        }
        return array('status' => 'ok', 'changes' => $changes);
    }

    /** ----- 2FA admin login gate ----- */
    private function is_admin_user($user) {
        if (!is_a($user, 'WP_User')) return false;
        return user_can($user, 'manage_options');
    }

    private function approval_active($username) {
        $approvals = (array) get_option(self::OPT_AUTH_APPROVALS, array());
        $now = time();
        if (!isset($approvals[$username])) return false;
        return ($now - (int) $approvals[$username]) <= self::AUTH_APPROVAL_TTL;
    }

    private function approval_grant($username) {
        $approvals = (array) get_option(self::OPT_AUTH_APPROVALS, array());
        // Cleanup stale
        $now = time();
        foreach ($approvals as $u => $t) {
            if (($now - (int) $t) > self::AUTH_APPROVAL_TTL) unset($approvals[$u]);
        }
        $approvals[$username] = $now;
        update_option(self::OPT_AUTH_APPROVALS, $approvals, false);
    }

    private function approval_revoke($username) {
        $approvals = (array) get_option(self::OPT_AUTH_APPROVALS, array());
        unset($approvals[$username]);
        update_option(self::OPT_AUTH_APPROVALS, $approvals, false);
    }

    public function gate_admin_login($user, $password = '') {
        if (!$this->get_setting('admin_2fa')) return $user;
        if (is_wp_error($user) || !$this->is_admin_user($user)) return $user;

        $username = $user->user_login;
        if ($this->approval_active($username)) {
            // Approved - consume and let through
            $this->approval_revoke($username);
            return $user;
        }

        // Push auth_request event and deny
        $this->push_event(array(
            'kind' => 'auth_request',
            'ip'   => $this->client_ip(),
            'user' => substr($username, 0, 32),
        ));

        return new WP_Error(
            'cyber_aegis_pending',
            __('<strong>Aegis Approval Required</strong><br>Admin login is awaiting hardware approval. Approve on your Cyber-Aegis device and try again within 2 minutes.', 'cyber-aegis')
        );
    }

    /** ----- SQLi pattern detection ----- */
    public function sqli_pattern_check() {
        if (!$this->get_setting('sqli_block')) return;
        if (is_user_logged_in() && current_user_can('manage_options')) return;

        $patterns = array(
            '/\bunion\s+select\b/i',
            '/\bor\s+1\s*=\s*1\b/i',
            '/\b(select|insert|update|delete|drop|alter)\s.+\bfrom\b/i',
            '/--\s*$/m',
            '/\/\*.*\*\//',
            '/\bsleep\s*\(/i',
            '/\bbenchmark\s*\(/i',
            '/load_file\s*\(/i',
            '/into\s+outfile/i',
        );

        $haystacks = array();
        $haystacks[] = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        foreach ($_GET as $v) {
            if (is_string($v)) $haystacks[] = $v;
        }
        foreach ($_POST as $v) {
            if (is_string($v)) $haystacks[] = $v;
        }

        foreach ($haystacks as $h) {
            foreach ($patterns as $p) {
                if (preg_match($p, $h)) {
                    $ip = $this->client_ip();
                    $this->push_event(array(
                        'kind' => 'sqli',
                        'ip'   => $ip,
                        'pattern' => substr($h, 0, 64),
                    ));
                    if ($this->get_setting('auto_ban')) {
                        $this->ban_ip_internal($ip, 'sqli');
                    }
                    wp_die(
                        '<h1>Blocked</h1><p>Suspicious request detected and blocked by Cyber-Aegis.</p>',
                        'Forbidden',
                        array('response' => 403)
                    );
                }
            }
        }
    }

    /** ----- XML-RPC block ----- */
    public function maybe_block_xmlrpc() {
        if (!$this->get_setting('block_xmlrpc')) return;
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            wp_die('XML-RPC disabled.', 'Forbidden', array('response' => 403));
        }
        add_filter('xmlrpc_enabled', '__return_false');
    }

    /** ----- User enumeration block (?author=N) ----- */
    public function maybe_block_user_enum() {
        if (!$this->get_setting('block_user_enum')) return;
        if (is_admin()) return;
        if (!isset($_GET['author'])) return;
        $a = $_GET['author'];
        if (is_array($a)) return;
        if (is_numeric($a) || preg_match('/^\d+$/', (string) $a)) {
            $ip = $this->client_ip();
            $this->push_event(array(
                'kind' => 'user_enum',
                'ip'   => $ip,
            ));
            wp_die('<h1>Forbidden</h1>', 'Forbidden', array('response' => 403));
        }
    }

    public function on_login_failed($username) {
        $username = (string) $username;
        $ip = $this->client_ip();
        $now = time();

        // Brute force tracking
        $tracker = (array) get_option(self::OPT_FAILED_LOGINS, array());
        if (!isset($tracker[$ip])) {
            $tracker[$ip] = array();
        }
        // Trim old attempts
        $tracker[$ip] = array_values(array_filter($tracker[$ip], function($t) use ($now) {
            return ($now - (int) $t) < self::BF_WINDOW_SEC;
        }));
        $tracker[$ip][] = $now;

        // Cleanup other stale IPs (keep map small)
        foreach ($tracker as $tip => $ts) {
            $tracker[$tip] = array_values(array_filter($ts, function($t) use ($now) {
                return ($now - (int) $t) < self::BF_WINDOW_SEC;
            }));
            if (empty($tracker[$tip])) {
                unset($tracker[$tip]);
            }
        }
        update_option(self::OPT_FAILED_LOGINS, $tracker, false);

        $this->push_event(array(
            'kind' => 'login_failed',
            'ip'   => $ip,
            'user' => substr((string) $username, 0, 32),
        ));

        if (count($tracker[$ip]) >= self::BF_THRESHOLD) {
            $this->push_event(array(
                'kind' => 'brute_force',
                'ip'   => $ip,
                'count'=> count($tracker[$ip]),
            ));
        }

        // Auto-ban after AUTO_BAN_THRESHOLD failed attempts
        if ($this->get_setting('auto_ban') && count($tracker[$ip]) >= self::AUTO_BAN_THRESHOLD) {
            $this->ban_ip_internal($ip, 'brute_force');
        }
    }

    public function on_login_success($user_login, $user = null) {
        $this->push_event(array(
            'kind' => 'login_ok',
            'ip'   => $this->client_ip(),
            'user' => substr((string) $user_login, 0, 32),
        ));
    }

    public function on_upgrade($upgrader = null, $info = array()) {
        $info = is_array($info) ? $info : array();
        $this->push_event(array(
            'kind' => 'upgrade',
            'type' => isset($info['type']) ? (string) $info['type'] : '?',
        ));
    }

    public function maybe_log_traffic() {
        // Only log front-end page hits (skip admin/ajax/rest)
        if (is_admin() || (defined('DOING_AJAX') && DOING_AJAX)) {
            return;
        }
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return;
        }
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        // Skip obvious bots to reduce noise
        if ($ua === '' || preg_match('/bot|crawler|spider|slurp/i', $ua)) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
        $uri = substr($uri, 0, 32);

        // Throttle: don't log same IP more than once per 30 seconds
        $ip = $this->client_ip();
        $cache_key = 'ca_traf_' . md5($ip);
        if (get_transient($cache_key)) {
            return;
        }
        set_transient($cache_key, 1, 30);

        $this->push_event(array(
            'kind' => 'traffic',
            'ip'   => $ip,
            'page' => $uri,
            'country' => $this->geo_country($ip),
        ));
    }

    public function device_key_ok($request) {
        $hdr = (string) $request->get_header('X-Cyber-Aegis-Device-Key');
        $stored = (string) get_option(self::OPT_DEVICE_KEY, '');
        return ($stored !== '' && hash_equals($stored, $hdr));
    }

    public function rest_authorized($request) {
        if ($this->device_key_ok($request)) {
            return true;
        }
        if (current_user_can('manage_options')) {
            $nonce = $request->get_header('X-WP-Nonce');
            return (bool) ($nonce && wp_verify_nonce($nonce, 'wp_rest'));
        }
        return false;
    }

    public function maybe_lockdown() {
        if (!get_option(self::OPT_LOCKDOWN, false)) {
            return;
        }
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        if (stripos($uri, 'wp-json') !== false) {
            return;
        }
        if (stripos($uri, 'wp-login.php') !== false) {
            return;
        }
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return;
        }
        if (current_user_can('manage_options') || is_user_logged_in()) {
            return;
        }
        wp_die(
            '<h1>Service unavailable</h1><p>This site is in security lockdown. Administrators may sign in.</p>',
            'Lockdown',
            array('response' => 503)
        );
    }

    public function firewall_blacklist() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        if ($ip === '') {
            return;
        }
        $blacklist = get_option(self::OPT_BLACKLIST, array());
        if (is_array($blacklist) && in_array($ip, $blacklist, true)) {
            wp_die('<h1>Access denied</h1><p>Your IP address has been blocked.</p>', 'Forbidden', array('response' => 403));
        }
    }

    public function admin_menu() {
        add_menu_page(
            __('Cyber-Aegis', 'cyber-aegis'),
            __('Cyber-Aegis', 'cyber-aegis'),
            'manage_options',
            'cyber-aegis',
            array($this, 'render_admin'),
            'dashicons-shield-alt',
            58
        );
    }

    public function enqueue_admin($hook) {
        if ($hook !== 'toplevel_page_cyber-aegis') {
            return;
        }
        wp_enqueue_script(
            'cyber-aegis-mqtt',
            'https://cdnjs.cloudflare.com/ajax/libs/mqtt/4.3.7/mqtt.min.js',
            array(),
            '4.3.7',
            true
        );
        wp_enqueue_style(
            'cyber-aegis-fonts',
            'https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;700&family=Orbitron:wght@400;700&display=swap',
            array(),
            '1.0.1'
        );
        wp_localize_script('cyber-aegis-mqtt', 'CyberAegisBridge', array(
            'rest'      => esc_url_raw(rest_url('cyber-aegis/v1/')),
            'nonce'     => wp_create_nonce('wp_rest'),
            'deviceKey' => (string) get_option(self::OPT_DEVICE_KEY, ''),
        ));
    }

    public function register_rest() {
        register_rest_route(
            'cyber-aegis/v1',
            '/status',
            array(
                'methods'             => 'GET',
                'callback'            => array($this, 'rest_status'),
                'permission_callback' => '__return_true',
            )
        );

        register_rest_route(
            'cyber-aegis/v1',
            '/hardware',
            array(
                'methods'             => 'POST',
                'callback'            => array($this, 'rest_hardware'),
                'permission_callback' => '__return_true',
            )
        );

        register_rest_route(
            'cyber-aegis/v1',
            '/blacklist',
            array(
                'methods'             => 'POST',
                'callback'            => array($this, 'rest_blacklist'),
                'permission_callback' => array($this, 'rest_authorized'),
            )
        );

        register_rest_route(
            'cyber-aegis/v1',
            '/events',
            array(
                'methods'             => 'GET',
                'callback'            => array($this, 'rest_events'),
                'permission_callback' => array($this, 'device_key_ok'),
            )
        );
    }

    /**
     * Returns events newer than `since` timestamp (default: last 60s).
     * Query: ?since=<unix_ts>&limit=<n>
     */
    public function rest_events(WP_REST_Request $request) {
        $since = (int) $request->get_param('since');
        if ($since <= 0) {
            $since = time() - 60;
        }
        $limit = (int) $request->get_param('limit');
        if ($limit <= 0 || $limit > self::MAX_EVENTS) {
            $limit = self::MAX_EVENTS;
        }

        $events = (array) get_option(self::OPT_EVENTS, array());
        $filtered = array();
        foreach ($events as $e) {
            if (!isset($e['t']) || (int) $e['t'] <= $since) {
                continue;
            }
            $filtered[] = $e;
            if (count($filtered) >= $limit) {
                break;
            }
        }

        return new WP_REST_Response(array(
            'now'      => time(),
            'events'   => $filtered,
            'lockdown' => (bool) get_option(self::OPT_LOCKDOWN, false),
        ), 200);
    }

    public function rest_status() {
        // Real update count from WordPress
        $updates_total = 0;
        if (function_exists('wp_get_update_data')) {
            $ud = wp_get_update_data();
            if (isset($ud['counts']['total'])) {
                $updates_total = (int) $ud['counts']['total'];
            }
        }
        return new WP_REST_Response(
            array(
                'wp'             => get_bloginfo('version'),
                'db'             => 'CONNECTED',
                'php'            => PHP_VERSION,
                'active_plugins' => count((array) get_option('active_plugins', array())),
                'updates'        => $updates_total,
                'banned_ips'     => count((array) get_option(self::OPT_BLACKLIST, array())),
                'lockdown'       => (bool) get_option(self::OPT_LOCKDOWN, false),
            ),
            200
        );
    }

    public function rest_hardware(WP_REST_Request $request) {
        if (!$this->device_key_ok($request)) {
            return new WP_Error('forbidden', 'Invalid or missing device key.', array('status' => 403));
        }
        $p = $request->get_json_params();
        if (!is_array($p)) {
            $p = array();
        }
        $cmd = isset($p['cmd']) ? sanitize_key((string) $p['cmd']) : sanitize_key((string) $request->get_param('cmd'));
        $ip  = isset($p['ip']) ? sanitize_text_field((string) $p['ip']) : sanitize_text_field((string) $request->get_param('ip'));

        switch ($cmd) {
            case 'ping':
                return new WP_REST_Response(array('ok' => true, 'cmd' => 'ping', 'time' => time()), 200);
            case 'lockdown':
                update_option(self::OPT_LOCKDOWN, true);
                do_action('cyber_aegis_lockdown', true);
                return new WP_REST_Response(array('ok' => true, 'lockdown' => true), 200);
            case 'unlock_site':
            case 'admin_unlock':
                update_option(self::OPT_LOCKDOWN, false);
                do_action('cyber_aegis_lockdown', false);
                return new WP_REST_Response(array('ok' => true, 'lockdown' => false), 200);
            case 'auth_approve':
                $user = isset($p['user']) ? sanitize_user((string) $p['user']) : '';
                if ($user === '') {
                    // Approve most recent pending request if no user specified
                    $events = (array) get_option(self::OPT_EVENTS, array());
                    foreach ($events as $e) {
                        if (isset($e['kind']) && $e['kind'] === 'auth_request' && !empty($e['user'])) {
                            $user = (string) $e['user'];
                            break;
                        }
                    }
                }
                if ($user !== '') {
                    $this->approval_grant($user);
                    $this->push_event(array('kind' => 'auth_approved', 'user' => $user));
                }
                do_action('cyber_aegis_auth_decision', 'approve', $p);
                return new WP_REST_Response(array('ok' => true, 'cmd' => 'auth_approve', 'user' => $user), 200);
            case 'auth_deny':
                $user = isset($p['user']) ? sanitize_user((string) $p['user']) : '';
                if ($user !== '') {
                    $this->approval_revoke($user);
                }
                $this->push_event(array('kind' => 'auth_denied', 'user' => $user));
                do_action('cyber_aegis_auth_decision', 'deny', $p);
                return new WP_REST_Response(array('ok' => true, 'cmd' => 'auth_deny', 'user' => $user), 200);
            case 'fim_check':
                $result = $this->fim_check();
                return new WP_REST_Response(array('ok' => true) + $result, 200);
            case 'fim_baseline':
                $b = $this->fim_baseline();
                return new WP_REST_Response(array('ok' => true, 'count' => count($b)), 200);
            case 'ban_ip':
            case 'ban_last_ip':
                if ($ip === '') {
                    return new WP_Error('bad_request', 'Missing ip.', array('status' => 400));
                }
                $blacklist = (array) get_option(self::OPT_BLACKLIST, array());
                if (!in_array($ip, $blacklist, true)) {
                    $blacklist[] = $ip;
                    update_option(self::OPT_BLACKLIST, array_values($blacklist));
                }
                return new WP_REST_Response(array('ok' => true, 'count' => count($blacklist)), 200);
            case 'unban_ip':
                if ($ip === '') {
                    return new WP_Error('bad_request', 'Missing ip.', array('status' => 400));
                }
                $blacklist = array_values(array_diff((array) get_option(self::OPT_BLACKLIST, array()), array($ip)));
                update_option(self::OPT_BLACKLIST, $blacklist);
                return new WP_REST_Response(array('ok' => true, 'count' => count($blacklist)), 200);
            default:
                return new WP_Error('bad_request', 'Unknown command.', array('status' => 400));
        }
    }

    public function rest_blacklist(WP_REST_Request $request) {
        if (!$this->rest_authorized($request)) {
            return new WP_Error('forbidden', 'Not allowed.', array('status' => 403));
        }
        $ip     = sanitize_text_field((string) $request->get_param('ip'));
        $action = sanitize_key((string) $request->get_param('action'));
        $blacklist = (array) get_option(self::OPT_BLACKLIST, array());
        if ($action === 'add' && $ip !== '' && !in_array($ip, $blacklist, true)) {
            $blacklist[] = $ip;
        } elseif ($action === 'remove' && $ip !== '') {
            $blacklist = array_values(array_diff($blacklist, array($ip)));
        }
        update_option(self::OPT_BLACKLIST, $blacklist);
        return new WP_REST_Response(array('status' => 'success', 'count' => count($blacklist)), 200);
    }

    public function render_admin() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_POST['ca_save']) && check_admin_referer('ca_save_key', 'ca_nonce')) {
            $key = isset($_POST['ca_device_key']) ? sanitize_text_field(wp_unslash($_POST['ca_device_key'])) : '';
            update_option(self::OPT_DEVICE_KEY, $key);
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Device key saved.', 'cyber-aegis') . '</p></div>';
        }

        if (isset($_POST['ca_save_settings']) && check_admin_referer('ca_settings', 'ca_settings_nonce')) {
            $new = array(
                'auto_ban'        => !empty($_POST['s_auto_ban']),
                'block_xmlrpc'    => !empty($_POST['s_block_xmlrpc']),
                'block_user_enum' => !empty($_POST['s_block_user_enum']),
                'admin_2fa'       => !empty($_POST['s_admin_2fa']),
                'geo_enabled'     => !empty($_POST['s_geo_enabled']),
                'sqli_block'      => !empty($_POST['s_sqli_block']),
            );
            update_option(self::OPT_SETTINGS, $new);
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Defense settings saved.', 'cyber-aegis') . '</p></div>';
        }

        if (isset($_POST['ca_fim_baseline']) && check_admin_referer('ca_fim', 'ca_fim_nonce')) {
            $b = $this->fim_baseline();
            echo '<div class="notice notice-success is-dismissible"><p>' . sprintf(esc_html__('FIM baseline created (%d files).', 'cyber-aegis'), count($b)) . '</p></div>';
        }

        if (isset($_POST['ca_fim_check']) && check_admin_referer('ca_fim', 'ca_fim_nonce')) {
            $r = $this->fim_check();
            $cnt = isset($r['changes']) ? count($r['changes']) : 0;
            echo '<div class="notice notice-' . ($cnt ? 'warning' : 'success') . ' is-dismissible"><p>' . sprintf(esc_html__('FIM check complete: %d changes detected.', 'cyber-aegis'), $cnt) . '</p></div>';
        }

        if (isset($_POST['ca_clear_bans']) && check_admin_referer('ca_clear', 'ca_clear_nonce')) {
            update_option(self::OPT_BLACKLIST, array());
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Blacklist cleared.', 'cyber-aegis') . '</p></div>';
        }

        $key_val  = (string) get_option(self::OPT_DEVICE_KEY, '');
        $ban_n    = count((array) get_option(self::OPT_BLACKLIST, array()));
        $settings = $this->settings();
        $fim_n    = count((array) get_option(self::OPT_FIM_BASELINE, array()));
        ?>
        <style>
            #wpbody-content { background: #000 !important; color: #00ff41; font-family: 'Fira Code', monospace; padding: 0; }
            .ca-aegis-keybox { max-width: 720px; margin: 10px 20px 0 0; padding: 16px; border: 1px solid #004400; background: rgba(0,10,0,0.85); color: #00ff41; }
            .ca-aegis-keybox h2 { font-family: 'Orbitron', sans-serif; color: #00ff41; margin: 0 0 10px; font-size: 14px; letter-spacing: 2px; }
            .ca-aegis-keybox p { color: #008800; font-size: 12px; margin: 0 0 12px; }
            .ca-aegis-keybox label { display: block; color: #00aa44; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; }
            .ca-aegis-keybox input[type="text"] { width: 100%; max-width: 520px; padding: 10px; background: #0a0a0a; color: #00ff41; border: 1px solid #00ff41; border-radius: 4px; font-family: inherit; font-size: 13px; box-sizing: border-box; }
            .ca-aegis-keybox .button-primary { background: #003300 !important; border-color: #00ff41 !important; color: #00ff41 !important; text-shadow: none !important; box-shadow: none !important; margin-top: 10px; }
            .ca-aegis-keybox .button-primary:hover { background: #00ff41 !important; color: #000 !important; }
            .matrix-v3 { position: relative; height: calc(100vh - 40px); background: #000; border: 1px solid #004400; margin: 10px 20px 0 0; overflow: hidden; display: grid; grid-template-rows: 60px 1fr 200px; }
            .m-canvas { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.08; pointer-events: none; }
            .m-header { z-index: 10; border-bottom: 2px solid #00ff41; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; background: rgba(0,20,0,0.8); }
            .m-header h2 { font-family: 'Orbitron', sans-serif; color: #00ff41; margin: 0; text-shadow: 0 0 10px #00ff41; letter-spacing: 2px; font-size: 16px; }
            .m-main { z-index: 10; display: grid; grid-template-columns: 1fr 350px; gap: 1px; background: #004400; overflow: hidden; }
            .m-terminal { background: #000; padding: 20px; overflow-y: auto; font-size: 13px; line-height: 1.45; }
            .m-sidebar { background: #000; padding: 20px; display: flex; flex-direction: column; gap: 15px; }
            .m-footer { z-index: 10; background: #000; border-top: 2px solid #00ff41; display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; padding: 15px; }
            .m-card { border: 1px solid #004400; padding: 10px; background: rgba(0,10,0,0.5); }
            .m-label { font-size: 10px; color: #008800; text-transform: uppercase; margin-bottom: 5px; }
            .m-val { font-size: 16px; font-weight: bold; }
            .m-line { margin: 4px 0; border-left: 2px solid #003300; padding-left: 10px; font-size: 13px; word-break: break-all; }
            .btn-action { background: none; border: 1px solid #00ff41; color: #00ff41; padding: 8px; cursor: pointer; font-family: inherit; font-size: 10px; width: 100%; margin-top: 5px; }
            .btn-action:hover { background: #00ff41; color: #000; }
            .pulse { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #ff1744; margin-right: 5px; vertical-align: middle; }
            .pulse.online { background: #00ff41; box-shadow: 0 0 10px #00ff41; }
        </style>

        <div class="ca-aegis-keybox">
            <h2>// SECURE_LINK</h2>
            <p><?php echo esc_html__('Paste the same key on the device provisioning page. REST base:', 'cyber-aegis'); ?> <code style="color:#00ffff;"><?php echo esc_html(rest_url('cyber-aegis/v1/')); ?></code></p>
            <form method="post">
                <?php wp_nonce_field('ca_save_key', 'ca_nonce'); ?>
                <label for="ca_device_key"><?php echo esc_html__('Device key', 'cyber-aegis'); ?></label>
                <input type="text" id="ca_device_key" name="ca_device_key" value="<?php echo esc_attr($key_val); ?>" autocomplete="off">
                <p><button type="submit" name="ca_save" class="button button-primary"><?php echo esc_html__('Save', 'cyber-aegis'); ?></button></p>
            </form>
        </div>

        <div class="ca-aegis-keybox">
            <h2>// DEFENSE_MATRIX</h2>
            <p><?php echo esc_html__('Active protections. Disable individually if compatibility issues arise.', 'cyber-aegis'); ?></p>
            <form method="post">
                <?php wp_nonce_field('ca_settings', 'ca_settings_nonce'); ?>
                <p><label style="display:inline-flex;align-items:center;gap:6px;text-transform:none;">
                    <input type="checkbox" name="s_auto_ban" value="1" <?php checked(!empty($settings['auto_ban'])); ?>>
                    <?php echo esc_html__('Auto-ban IP after 10 failed logins or SQLi attempt', 'cyber-aegis'); ?>
                </label></p>
                <p><label style="display:inline-flex;align-items:center;gap:6px;text-transform:none;">
                    <input type="checkbox" name="s_admin_2fa" value="1" <?php checked(!empty($settings['admin_2fa'])); ?>>
                    <?php echo esc_html__('Hardware 2FA: admin logins require ESP approval (K3 on DASH tab)', 'cyber-aegis'); ?>
                </label></p>
                <p><label style="display:inline-flex;align-items:center;gap:6px;text-transform:none;">
                    <input type="checkbox" name="s_sqli_block" value="1" <?php checked(!empty($settings['sqli_block'])); ?>>
                    <?php echo esc_html__('Block SQL-injection patterns in URL/POST', 'cyber-aegis'); ?>
                </label></p>
                <p><label style="display:inline-flex;align-items:center;gap:6px;text-transform:none;">
                    <input type="checkbox" name="s_block_xmlrpc" value="1" <?php checked(!empty($settings['block_xmlrpc'])); ?>>
                    <?php echo esc_html__('Disable XML-RPC (prevents pingback DDoS / xmlrpc brute force)', 'cyber-aegis'); ?>
                </label></p>
                <p><label style="display:inline-flex;align-items:center;gap:6px;text-transform:none;">
                    <input type="checkbox" name="s_block_user_enum" value="1" <?php checked(!empty($settings['block_user_enum'])); ?>>
                    <?php echo esc_html__('Block user enumeration (?author=N and /wp/v2/users)', 'cyber-aegis'); ?>
                </label></p>
                <p><label style="display:inline-flex;align-items:center;gap:6px;text-transform:none;">
                    <input type="checkbox" name="s_geo_enabled" value="1" <?php checked(!empty($settings['geo_enabled'])); ?>>
                    <?php echo esc_html__('Enable Geo-IP lookup for traffic events (ip-api.com)', 'cyber-aegis'); ?>
                </label></p>
                <p><button type="submit" name="ca_save_settings" class="button button-primary"><?php echo esc_html__('Save defenses', 'cyber-aegis'); ?></button></p>
            </form>
        </div>

        <div class="ca-aegis-keybox">
            <h2>// FILE_INTEGRITY</h2>
            <p><?php echo esc_html(sprintf(__('Tracking %d core files. Hourly cron also checks automatically.', 'cyber-aegis'), $fim_n)); ?></p>
            <form method="post" style="display:flex;gap:10px;">
                <?php wp_nonce_field('ca_fim', 'ca_fim_nonce'); ?>
                <button type="submit" name="ca_fim_baseline" class="button button-primary"><?php echo esc_html__('Create / refresh baseline', 'cyber-aegis'); ?></button>
                <button type="submit" name="ca_fim_check" class="button button-primary"><?php echo esc_html__('Run check now', 'cyber-aegis'); ?></button>
            </form>
        </div>

        <div class="ca-aegis-keybox">
            <h2>// BLACKLIST</h2>
            <p><?php echo esc_html(sprintf(__('%d IPs currently blocked.', 'cyber-aegis'), $ban_n)); ?></p>
            <form method="post" onsubmit="return confirm('Clear all banned IPs?');">
                <?php wp_nonce_field('ca_clear', 'ca_clear_nonce'); ?>
                <button type="submit" name="ca_clear_bans" class="button button-primary"><?php echo esc_html__('Clear blacklist', 'cyber-aegis'); ?></button>
            </form>
        </div>

        <div class="matrix-v3">
            <canvas id="ca_mc" class="m-canvas"></canvas>
            <header class="m-header">
                <h2>CYBER-AEGIS // MATRIX_CORE</h2>
                <div id="status-tag"><div id="p-led" class="pulse"></div>LINK: <span id="p-txt">OFFLINE</span></div>
            </header>
            <main class="m-main">
                <div class="m-terminal" id="mt">
                    <div class="m-line" style="color:#00ff41">&gt;&gt; Bridge online. Monitoring hardware node…</div>
                </div>
                <aside class="m-sidebar">
                    <div class="m-card">
                        <div class="m-label">Malware radar</div>
                        <div class="m-val">SECURE</div>
                        <button type="button" class="btn-action" id="ca-btn-scan"><?php echo esc_html__('Deep scan', 'cyber-aegis'); ?></button>
                    </div>
                    <div class="m-card">
                        <div class="m-label">SQLi guard</div>
                        <div class="m-val" id="sqli-stat" style="color:#00ff41">ACTIVE</div>
                    </div>
                    <div class="m-card">
                        <div class="m-label">Banned IPs</div>
                        <div class="m-val" id="ban-count"><?php echo (int) $ban_n; ?></div>
                    </div>
                </aside>
            </main>
            <footer class="m-footer">
                <div class="m-card"><div class="m-label">Node</div><div id="node-name" class="m-val">—</div></div>
                <div class="m-card"><div class="m-label">State</div><div class="m-val">STABLE</div></div>
                <div class="m-card"><div class="m-label">API</div><div class="m-val">v1</div></div>
                <div class="m-card"><div class="m-label">Channel</div><div id="proto-info" class="m-val">—</div></div>
            </footer>
        </div>

        <script>
        (function() {
            var c = document.getElementById('ca_mc');
            if (c) {
                var x = c.getContext('2d');
                c.width = window.innerWidth;
                c.height = window.innerHeight;
                var chars = '0123456789ABCDEF', f = 12, cols = Math.floor(c.width / f), drops = Array(cols).fill(1);
                function matrixRain() {
                    x.fillStyle = 'rgba(0,0,0,0.05)';
                    x.fillRect(0, 0, c.width, c.height);
                    x.fillStyle = '#00ff41';
                    x.font = f + 'px monospace';
                    for (var i = 0; i < cols; i++) {
                        var ch = chars[Math.floor(Math.random() * chars.length)];
                        var y = drops[i] * f;
                        x.fillText(ch, i * f, y);
                        if (y > c.height && Math.random() > 0.975) drops[i] = 0;
                        drops[i]++;
                    }
                }
                setInterval(matrixRain, 50);
            }

            function al(m, cl) {
                var l = document.createElement('div');
                l.className = 'm-line';
                if (cl) l.style.color = cl;
                l.textContent = '[' + new Date().toLocaleTimeString() + '] ' + m;
                var mt = document.getElementById('mt');
                if (mt) mt.prepend(l);
            }

            function banIP(ip) {
                if (!ip) return;
                var h = { 'Content-Type': 'application/json', 'X-WP-Nonce': CyberAegisBridge.nonce };
                if (CyberAegisBridge.deviceKey) h['X-Cyber-Aegis-Device-Key'] = CyberAegisBridge.deviceKey;
                fetch(CyberAegisBridge.rest + 'blacklist', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: h,
                    body: JSON.stringify({ ip: ip, action: 'add' })
                }).then(function(r) { return r.json(); }).then(function(data) {
                    al('BLACKLIST >> ' + ip, '#ff1744');
                    var el = document.getElementById('ban-count');
                    if (el && typeof data.count === 'number') el.textContent = data.count;
                }).catch(function(e) { al('BLACKLIST_ERR >> ' + e, '#ff9800'); });
            }

            function initMQTT() {
                if (typeof mqtt === 'undefined') { setTimeout(initMQTT, 400); return; }
                var isSSL = window.location.protocol === 'https:';
                var brokerUrl = isSSL ? 'wss://broker.hivemq.com:8884/mqtt' : 'ws://broker.hivemq.com:8000/mqtt';
                var client = mqtt.connect(brokerUrl, {
                    clientId: 'ca_matrix_' + Math.random().toString(16).slice(2, 10),
                    clean: true,
                    keepalive: 60
                });
                var hbt;
                client.on('connect', function() {
                    al('MQTT sync established.', '#fff');
                    var pi = document.getElementById('proto-info');
                    if (pi) pi.textContent = isSSL ? 'WSS' : 'WS';
                    client.subscribe('cyber_aegis/#');
                });
                function forwardHardwareCmd(j) {
                    if (!j || !j.cmd) return;
                    var headers = { 'Content-Type': 'application/json', 'X-WP-Nonce': CyberAegisBridge.nonce };
                    if (CyberAegisBridge.deviceKey) headers['X-Cyber-Aegis-Device-Key'] = CyberAegisBridge.deviceKey;
                    fetch(CyberAegisBridge.rest + 'hardware', {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: headers,
                        body: JSON.stringify(j)
                    }).then(function(r) { return r.json().catch(function() { return {}; }); })
                      .then(function(res) {
                          al('CMD ' + j.cmd + ' >> ' + (res && res.ok ? 'OK' : 'ERR'), res && res.ok ? '#00ff41' : '#ff1744');
                          if (res && typeof res.lockdown === 'boolean') {
                              al('Lockdown is now ' + (res.lockdown ? 'ON' : 'OFF'), res.lockdown ? '#ff1744' : '#00ff41');
                          }
                          if (res && typeof res.count === 'number') {
                              var be = document.getElementById('ban-count');
                              if (be) be.textContent = res.count;
                          }
                      })
                      .catch(function(e) { al('CMD ERR >> ' + e, '#ff9800'); });
                }

                client.on('message', function(t, buf) {
                    var msg = buf.toString();
                    var j = {};
                    try { j = JSON.parse(msg); } catch (e1) { j = {}; }
                    if (t === 'cyber_aegis/heartbeat') {
                        var led = document.getElementById('p-led');
                        var txt = document.getElementById('p-txt');
                        var node = document.getElementById('node-name');
                        if (led) led.classList.add('online');
                        if (txt) txt.textContent = 'ONLINE';
                        if (node) node.textContent = j.device || 'ESP32';
                        clearTimeout(hbt);
                        hbt = setTimeout(function() {
                            if (led) led.classList.remove('online');
                            if (txt) txt.textContent = 'OFFLINE';
                        }, 12000);
                    }
                    if (t === 'cyber_aegis/hardware/command') {
                        if (j.cmd === 'ban_last_ip' || j.cmd === 'ban_ip') {
                            banIP(j.ip);
                        } else {
                            // Forward all other hardware commands to REST API
                            forwardHardwareCmd(j);
                        }
                    }
                    al('[' + t + '] ' + msg, '#00e5ff');
                });

                async function remoteCmd(cmd) {
                    try {
                        if (CyberAegisBridge.deviceKey) {
                            await fetch(CyberAegisBridge.rest + 'hardware', {
                                method: 'POST',
                                credentials: 'same-origin',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-Cyber-Aegis-Device-Key': CyberAegisBridge.deviceKey
                                },
                                body: JSON.stringify({ cmd: cmd })
                            });
                        }
                    } catch (e2) { al('REST >> ' + e2, '#ff9800'); }
                    client.publish('cyber_aegis/remote_control', JSON.stringify({ cmd: cmd }));
                }
                window.cyberAegisRemote = remoteCmd;
                window.sc = remoteCmd;
            }

            document.getElementById('ca-btn-scan').addEventListener('click', function() {
                al('SCAN >> Core integrity check (placeholder)', '#00e5ff');
            });

            initMQTT();
        })();
        </script>
        <?php
    }
}

new Cyber_Aegis_Bridge();

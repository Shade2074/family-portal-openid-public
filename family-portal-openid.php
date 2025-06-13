<?php
/**
 * Plugin Name: Family Portal OpenID Connect
 * Plugin URI: https://github.com/Shade2074/family-portal-openid
 * Description: Custom OpenID Connect authentication plugin for Family Portal with Keycloak group-based role mapping. Designed specifically for self-hosted family portals.
 * Version: 1.1.1
 * Author: Shade2074
 * License: MIT
 * Text Domain: family-portal-openid
 * Network: false
 * 
 * This plugin provides secure OpenID Connect authentication with automatic role assignment
 * based on Keycloak group membership. Built for the Family Portal project.
 * 
 * Version 1.1.1 Changes:
 * - Updated for external domain access (your_domain.com)
 * - Fixed hardcoded internal IP addresses
 * - Updated Keycloak URLs for reverse proxy compatibility
 * 
 * Version 1.1.0 Changes:
 * - Enhanced single logout functionality (clears both WordPress AND Keycloak sessions)
 * - Professional SVG eye icons for password toggle
 * - Improved admin interface and debugging
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('FPOIDC_VERSION', '1.1.1');
define('FPOIDC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('FPOIDC_PLUGIN_URL', plugin_dir_url(__FILE__));
define('FPOIDC_PLUGIN_FILE', __FILE__);

/**
 * Main Family Portal OpenID Connect Plugin Class
 */
class YourRealmOpenIDConnect {
    
    private static $instance = null;
    
    /**
     * Get singleton instance
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        add_action('init', array($this, 'init'));
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }
    
    /**
     * Initialize the plugin
     */
    public function init() {
        // Load text domain for translations
        load_plugin_textdomain('family-portal-openid', false, dirname(plugin_basename(__FILE__)) . '/languages');
        
        // Initialize admin interface
        if (is_admin()) {
            $this->initAdmin();
        }
        
        // Initialize authentication handlers
        $this->initAuth();
        
        // Add login button to WordPress login form
        add_action('login_form', array($this, 'addLoginButton'));
    }
    
    /**
     * Initialize admin interface
     */
    private function initAdmin() {
        add_action('admin_menu', array($this, 'addAdminMenu'));
        add_action('admin_init', array($this, 'registerSettings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueueAdminScripts'));
    }
    
    /**
     * Initialize authentication handlers
     */
    private function initAuth() {
        // Handle OpenID Connect callbacks
        add_action('wp_loaded', array($this, 'handleCallback'));
        
        // Handle logout with single logout functionality
        add_action('wp_logout', array($this, 'handleLogout'));
    }
    
    /**
     * Enqueue admin scripts
     */
    public function enqueueAdminScripts($hook) {
        if ($hook !== 'settings_page_family-portal-openid') {
            return;
        }
        
        // Add inline script for professional SVG eye toggle
        wp_add_inline_script('jquery', '
            jQuery(document).ready(function($) {
                // Add password toggle button with professional SVG icons
                var $secretField = $("input[name=\'fpoidc_client_secret\']");
                if ($secretField.length) {
                    // Wrap field in relative container
                    $secretField.wrap("<div style=\'position: relative; display: inline-block;\'></div>");
                    
                    // Define professional SVG eye icons
                    var eyeOpenSVG = \'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0088FF" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>\';
                    var eyeClosedSVG = \'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0088FF" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>\';
                    
                    // Add the toggle button with closed eye initially
                    $secretField.after(\'<button type="button" id="toggle-secret" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; padding: 4px; transition: all 0.3s ease; border-radius: 3px;">\' + eyeClosedSVG + \'</button>\');
                    
                    // Toggle functionality with SVG icons
                    $("#toggle-secret").on("click", function() {
                        var $this = $(this);
                        var type = $secretField.attr("type") === "password" ? "text" : "password";
                        
                        $secretField.attr("type", type);
                        
                        if (type === "password") {
                            // Hidden: show closed/crossed eye
                            $this.html(eyeClosedSVG);
                        } else {
                            // Visible: show open eye
                            $this.html(eyeOpenSVG);
                        }
                    });
                    
                    // Hover effects for better UX
                    $("#toggle-secret").hover(
                        function() { 
                            $(this).css({"background-color": "#f0f8ff", "transform": "translateY(-50%) scale(1.1)"}); 
                        },
                        function() { 
                            $(this).css({"background-color": "transparent", "transform": "translateY(-50%) scale(1)"}); 
                        }
                    );
                }
            });
        ');
    }
    
    /**
     * Add admin menu
     */
    public function addAdminMenu() {
        add_options_page(
            'Family Portal OpenID Connect',
            'Family Portal Auth',
            'manage_options',
            'family-portal-openid',
            array($this, 'adminPage')
        );
    }
    
    /**
     * Register plugin settings
     */
    public function registerSettings() {
        register_setting('fpoidc_settings', 'fpoidc_keycloak_url');
        register_setting('fpoidc_settings', 'fpoidc_realm');
        register_setting('fpoidc_settings', 'fpoidc_client_id');
        register_setting('fpoidc_settings', 'fpoidc_client_secret');
        register_setting('fpoidc_settings', 'fpoidc_admin_group');
        register_setting('fpoidc_settings', 'fpoidc_default_role');
        register_setting('fpoidc_settings', 'fpoidc_debug_mode');
        register_setting('fpoidc_settings', 'fpoidc_logout_redirect_url');
    }
    
    /**
     * Admin page content
     */
    public function adminPage() {
        ?>
        <div class="wrap">
            <h1>Family Portal OpenID Connect Settings</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('fpoidc_settings');
                do_settings_sections('fpoidc_settings');
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row">Keycloak Server URL</th>
                        <td>
                            <input type="url" name="fpoidc_keycloak_url" value="<?php echo esc_attr(get_option('fpoidc_keycloak_url', 'https://your_domain.com:8080')); ?>" class="regular-text" />
                            <p class="description">Base URL of your Keycloak server (e.g., https://your_domain.com:8080)</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Realm</th>
                        <td>
                            <input type="text" name="fpoidc_realm" value="<?php echo esc_attr(get_option('fpoidc_realm', 'YourRealm')); ?>" class="regular-text" />
                            <p class="description">Keycloak realm name</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Client ID</th>
                        <td>
                            <input type="text" name="fpoidc_client_id" value="<?php echo esc_attr(get_option('fpoidc_client_id', 'your-wordpress-client')); ?>" class="regular-text" />
                            <p class="description">OpenID Connect client ID</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Client Secret</th>
                        <td>
                            <input type="password" name="fpoidc_client_secret" value="<?php echo esc_attr(get_option('fpoidc_client_secret')); ?>" class="regular-text" />
                            <p class="description">OpenID Connect client secret (stored securely) - Click the eye to reveal/hide</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Admin Group Name</th>
                        <td>
                            <input type="text" name="fpoidc_admin_group" value="<?php echo esc_attr(get_option('fpoidc_admin_group', 'Admin')); ?>" class="regular-text" />
                            <p class="description">Keycloak group name for WordPress administrators</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Default Role</th>
                        <td>
                            <select name="fpoidc_default_role">
                                <?php
                                $roles = wp_roles()->roles;
                                $selected_role = get_option('fpoidc_default_role', 'subscriber');
                                foreach ($roles as $role_key => $role) {
                                    echo '<option value="' . esc_attr($role_key) . '"' . selected($selected_role, $role_key, false) . '>' . esc_html($role['name']) . '</option>';
                                }
                                ?>
                            </select>
                            <p class="description">Default WordPress role for new users</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Logout Redirect URL</th>
                        <td>
                            <input type="url" name="fpoidc_logout_redirect_url" value="<?php echo esc_attr(get_option('fpoidc_logout_redirect_url', 'https://your_domain.com/')); ?>" class="regular-text" />
                            <p class="description">Where users should be redirected after logout (e.g., https://your_domain.com/)</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Debug Mode</th>
                        <td>
                            <label>
                                <input type="checkbox" name="fpoidc_debug_mode" value="1" <?php checked(get_option('fpoidc_debug_mode'), 1); ?> />
                                Enable debug logging (helps troubleshoot authentication issues)
                            </label>
                            <p class="description">When enabled, detailed logs will be written to WordPress debug.log</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
            
            <h2>Current Status</h2>
            <p><strong>Plugin Version:</strong> <?php echo FPOIDC_VERSION; ?></p>
            <p><strong>Authentication Status:</strong> 
                <?php if ($this->isConfigured()) : ?>
                    <span style="color: green;">✅ Configured</span>
                <?php else : ?>
                    <span style="color: red;">❌ Not Configured</span>
                <?php endif; ?>
            </p>
            <p><strong>Logout Redirect:</strong> <?php echo esc_html(get_option('fpoidc_logout_redirect_url', 'https://your_domain.com/')); ?></p>
            <p><strong>Single Logout:</strong> <span style="color: green;">✅ Enabled (v1.1.0 feature)</span></p>
            
            <h2>Callback URLs for Keycloak Configuration</h2>
            <p><strong>Redirect URI:</strong><br>
            <code><?php echo home_url('/wp-admin/admin-ajax.php?action=fpoidc_callback'); ?></code></p>
            <p><strong>Post Logout Redirect URI:</strong><br>
            <code><?php echo esc_html(get_option('fpoidc_logout_redirect_url', 'https://your_domain.com/')); ?></code></p>
            <p><em>Use these exact URLs in your Keycloak client configuration.</em></p>
            
            <?php if (get_option('fpoidc_debug_mode')): ?>
            <h2>Debug Information</h2>
            <p><strong>WordPress Home URL:</strong> <?php echo home_url(); ?></p>
            <p><strong>Current User:</strong> <?php echo wp_get_current_user()->user_login; ?></p>
            <p><strong>PHP Version:</strong> <?php echo PHP_VERSION; ?></p>
            <?php endif; ?>
        </div>
        <?php
    }
    
    /**
     * Check if plugin is properly configured
     */
    private function isConfigured() {
        $required_settings = ['fpoidc_keycloak_url', 'fpoidc_realm', 'fpoidc_client_id', 'fpoidc_client_secret'];
        foreach ($required_settings as $setting) {
            if (empty(get_option($setting))) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Debug logging
     */
    private function debugLog($message) {
        if (get_option('fpoidc_debug_mode') && function_exists('error_log')) {
            error_log('[Family Portal OpenID] ' . $message);
        }
    }
    
    /**
     * Add login button to WordPress login form
     */
    public function addLoginButton() {
        if (!$this->isConfigured()) {
            return;
        }
        
        $login_url = $this->getAuthorizationUrl();
        ?>
        <p style="text-align: center; margin: 20px 0;">
            <a href="<?php echo esc_url($login_url); ?>" class="button button-primary" style="width: 100%; padding: 12px; font-size: 16px;">
                🔐 Login with Family Portal
            </a>
        </p>
        <div style="text-align: center; margin: 10px 0; color: #666;">
            <small>Use your Family Portal account to sign in</small>
        </div>
        <?php
    }
    
    /**
     * Get Keycloak authorization URL
     */
    private function getAuthorizationUrl() {
        $keycloak_url = get_option('fpoidc_keycloak_url');
        $realm = get_option('fpoidc_realm');
        $client_id = get_option('fpoidc_client_id');
        $redirect_uri = home_url('/wp-admin/admin-ajax.php?action=fpoidc_callback');
        $state = wp_create_nonce('fpoidc_auth_' . time());
        
        // Store state in WordPress transients for validation (more reliable than sessions)
        set_transient('fpoidc_state_' . $state, $state, 600); // 10 minutes expiry
        
        $params = array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'openid email profile groups',
            'state' => $state
        );
        
        $auth_url = $keycloak_url . '/realms/' . $realm . '/protocol/openid-connect/auth?' . http_build_query($params);
        $this->debugLog('Generated authorization URL: ' . $auth_url);
        
        return $auth_url;
    }
    
    /**
     * Handle OpenID Connect callback
     */
    public function handleCallback() {
        if (!isset($_GET['action']) || $_GET['action'] !== 'fpoidc_callback') {
            return;
        }
        
        $this->debugLog('Callback received with parameters: ' . print_r($_GET, true));
        
        // Check for error from Keycloak
        if (isset($_GET['error'])) {
            $error = sanitize_text_field($_GET['error']);
            $error_description = isset($_GET['error_description']) ? sanitize_text_field($_GET['error_description']) : '';
            $this->debugLog('Keycloak error: ' . $error . ' - ' . $error_description);
            wp_die('Authentication error from Keycloak: ' . $error . '<br>Description: ' . $error_description);
        }
        
        // Verify state parameter using transients
        $received_state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        $stored_state = get_transient('fpoidc_state_' . $received_state);
        
        $this->debugLog('State verification - Received: ' . $received_state . ', Stored: ' . $stored_state);
        
        if (empty($received_state) || empty($stored_state) || $received_state !== $stored_state) {
            $this->debugLog('State parameter mismatch or missing');
            wp_die('Invalid or missing state parameter. Authentication failed for security reasons.');
        }
        
        // Clear the state
        delete_transient('fpoidc_state_' . $received_state);
        
        // Check for authorization code
        if (!isset($_GET['code'])) {
            $this->debugLog('No authorization code received');
            wp_die('Authorization code not received. Authentication failed.');
        }
        
        $code = sanitize_text_field($_GET['code']);
        $this->debugLog('Authorization code received: ' . substr($code, 0, 10) . '...');
        
        // Exchange code for tokens
        $tokens = $this->exchangeCodeForTokens($code);
        if (!$tokens) {
            wp_die('Failed to exchange authorization code for tokens. Check debug logs for details.');
        }
        
        // Get user info from Keycloak
        $user_info = $this->getUserInfo($tokens['access_token']);
        if (!$user_info) {
            wp_die('Failed to retrieve user information from Keycloak.');
        }
        
        $this->debugLog('User info retrieved: ' . print_r($user_info, true));
        
        // Create or update WordPress user
        $wp_user = $this->createOrUpdateUser($user_info);
        if (!$wp_user) {
            wp_die('Failed to create or update WordPress user.');
        }
        
        // Log the user in
        wp_set_current_user($wp_user->ID);
        wp_set_auth_cookie($wp_user->ID, true);
        
        $this->debugLog('User successfully logged in: ' . $wp_user->user_login);
        
        // Redirect to admin dashboard
        wp_redirect(admin_url());
        exit;
    }
    
    /**
     * Exchange authorization code for tokens
     */
    private function exchangeCodeForTokens($code) {
        $keycloak_url = get_option('fpoidc_keycloak_url');
        $realm = get_option('fpoidc_realm');
        $client_id = get_option('fpoidc_client_id');
        $client_secret = get_option('fpoidc_client_secret');
        $redirect_uri = home_url('/wp-admin/admin-ajax.php?action=fpoidc_callback');
        
        $token_url = $keycloak_url . '/realms/' . $realm . '/protocol/openid-connect/token';
        
        $body = array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirect_uri,
            'client_id' => $client_id,
            'client_secret' => $client_secret
        );
        
        $this->debugLog('Token exchange URL: ' . $token_url);
        $this->debugLog('Token exchange body: ' . print_r(array_merge($body, array('client_secret' => '[HIDDEN]')), true));
        
        $response = wp_remote_post($token_url, array(
            'body' => $body,
            'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            $this->debugLog('Token exchange error: ' . $response->get_error_message());
            return false;
        }
        
        $http_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        $this->debugLog('Token exchange response code: ' . $http_code);
        $this->debugLog('Token exchange response body: ' . $body);
        
        if ($http_code !== 200) {
            $this->debugLog('Token exchange failed with HTTP code: ' . $http_code);
            return false;
        }
        
        $data = json_decode($body, true);
        
        if (!isset($data['access_token'])) {
            $this->debugLog('No access token in response');
            return false;
        }
        
        $this->debugLog('Token exchange successful');
        return $data;
    }
    
    /**
     * Get user info from Keycloak
     */
    private function getUserInfo($access_token) {
        $keycloak_url = get_option('fpoidc_keycloak_url');
        $realm = get_option('fpoidc_realm');
        
        $userinfo_url = $keycloak_url . '/realms/' . $realm . '/protocol/openid-connect/userinfo';
        
        $this->debugLog('Userinfo URL: ' . $userinfo_url);
        
        $response = wp_remote_get($userinfo_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token
            ),
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            $this->debugLog('Userinfo request error: ' . $response->get_error_message());
            return false;
        }
        
        $http_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        $this->debugLog('Userinfo response code: ' . $http_code);
        $this->debugLog('Userinfo response body: ' . $body);
        
        if ($http_code !== 200) {
            return false;
        }
        
        return json_decode($body, true);
    }
    
    /**
     * Create or update WordPress user
     */
    private function createOrUpdateUser($user_info) {
        $email = $user_info['email'];
        $username = isset($user_info['preferred_username']) ? $user_info['preferred_username'] : $email;
        $first_name = isset($user_info['given_name']) ? $user_info['given_name'] : '';
        $last_name = isset($user_info['family_name']) ? $user_info['family_name'] : '';
        $groups = isset($user_info['groups']) ? $user_info['groups'] : array();
        
        $this->debugLog('Processing user - Email: ' . $email . ', Groups: ' . print_r($groups, true));
        
        // Check if user already exists
        $existing_user = get_user_by('email', $email);
        
        if ($existing_user) {
            // Update existing user
            $user_id = $existing_user->ID;
            wp_update_user(array(
                'ID' => $user_id,
                'first_name' => $first_name,
                'last_name' => $last_name
            ));
            $this->debugLog('Updated existing user: ' . $user_id);
        } else {
            // Create new user
            $user_id = wp_create_user($username, wp_generate_password(), $email);
            
            if (is_wp_error($user_id)) {
                $this->debugLog('Failed to create user: ' . $user_id->get_error_message());
                return false;
            }
            
            wp_update_user(array(
                'ID' => $user_id,
                'first_name' => $first_name,
                'last_name' => $last_name
            ));
            
            $this->debugLog('Created new user: ' . $user_id);
        }
        
        // Assign role based on groups
        $user = get_user_by('id', $user_id);
        $admin_group = get_option('fpoidc_admin_group', 'Admin');
        $default_role = get_option('fpoidc_default_role', 'subscriber');
        
        if (in_array($admin_group, $groups)) {
            $user->set_role('administrator');
            $this->debugLog('Assigned administrator role to user (in group: ' . $admin_group . ')');
        } else {
            $user->set_role($default_role);
            $this->debugLog('Assigned default role (' . $default_role . ') to user');
        }
        
        return $user;
    }
    
    /**
     * Handle logout - Enhanced Single Logout (WordPress + Keycloak)
     * This function clears BOTH WordPress session AND Keycloak session
     * NEW in v1.1.0: Enterprise-grade single logout functionality
     */
    public function handleLogout() {
        // Get the configured logout redirect URL
        $logout_redirect_url = get_option('fpoidc_logout_redirect_url', 'https://your_domain.com/');
        
        // Log the logout for debugging
        $this->debugLog('User logout initiated - implementing single logout');
        
        // Build Keycloak logout URL to terminate the Keycloak session
        $keycloak_url = get_option('fpoidc_keycloak_url');
        $realm = get_option('fpoidc_realm');
        
        if (!empty($keycloak_url) && !empty($realm)) {
            // Construct Keycloak logout endpoint
            $keycloak_logout_url = $keycloak_url . '/realms/' . $realm . '/protocol/openid-connect/logout';
            
            // Add post_logout_redirect_uri parameter to redirect back to our site after Keycloak logout
            $keycloak_logout_params = array(
                'post_logout_redirect_uri' => $logout_redirect_url,
                'client_id' => get_option('fpoidc_client_id', 'your-wordpress-client')
            );
            
            $full_keycloak_logout_url = $keycloak_logout_url . '?' . http_build_query($keycloak_logout_params);
            
            $this->debugLog('Redirecting to Keycloak logout: ' . $full_keycloak_logout_url);
            
            // Redirect to Keycloak logout endpoint
            // This will:
            // 1. Clear the Keycloak session
            // 2. Redirect back to our configured logout URL
            wp_redirect($full_keycloak_logout_url);
            exit;
        } else {
            // Fallback: if Keycloak is not configured, just redirect to logout URL
            $this->debugLog('Keycloak not configured - falling back to simple redirect: ' . $logout_redirect_url);
            wp_redirect($logout_redirect_url);
            exit;
        }
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        // Set default options
        if (!get_option('fpoidc_keycloak_url')) {
            update_option('fpoidc_keycloak_url', 'https://your_domain.com:8080');
        }
        if (!get_option('fpoidc_realm')) {
            update_option('fpoidc_realm', 'YourRealm');
        }
        if (!get_option('fpoidc_client_id')) {
            update_option('fpoidc_client_id', 'your-wordpress-client');
        }
        if (!get_option('fpoidc_admin_group')) {
            update_option('fpoidc_admin_group', 'Admin');
        }
        if (!get_option('fpoidc_default_role')) {
            update_option('fpoidc_default_role', 'subscriber');
        }
        if (!get_option('fpoidc_logout_redirect_url')) {
            update_option('fpoidc_logout_redirect_url', 'https://your_domain.com/');
        }
    }
    
    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Clean up if needed
    }
}

// Initialize the plugin
YourRealmOpenIDConnect::getInstance();

/* ------------------------------ */
/*    LOGIN-PAGE APPEARANCE CSS   */
/* ------------------------------ */
add_action('login_enqueue_scripts', 'family_portal_custom_login_page');
function family_portal_custom_login_page() {
    ?>
    <style type="text/css">
        /* Hide default WordPress elements */
        #loginform, .login-action-login #nav, .login-action-login #backtoblog {
            display: none !important;
        }
        
        /* Full page background */
        body.login {
            background: url('<?php echo plugins_url('background.jpg', __FILE__); ?>') no-repeat center center fixed !important;
            background-size: cover !important;
            margin: 0;
            padding: 0;
            height: 100vh;
            overflow: hidden;
        }
        
        /* Main login container */
        #login {
            width: 100% !important;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            padding: 0 !important;
        }
        
        /* Portal button container */
        .portal-button-container {
            text-align: center;
            z-index: 10;
        }
        
        /* Portal button styling */
        .portal-button {
            cursor: pointer;
            transition: transform 0.3s ease, filter 0.3s ease;
            max-width: 300px;
            height: auto;
            border: none;
            background: none;
            padding: 0;
        }
        
        .portal-button:hover {
            transform: scale(1.05);
            filter: brightness(1.1);
        }
        
        /* Gnome container - lower left corner */
        .gnome-container {
            position: fixed;
            bottom: 20px;
            left: 20px;
            z-index: 20;
        }
        
        /* Gnome image */
        .gnome-toggle {
            width: 80px;
            height: auto;
            cursor: pointer;
            transition: transform 0.3s ease;
        }
        
        .gnome-toggle:hover {
            transform: scale(1.1);
        }
        
        /* Admin panel - hidden by default */
        .admin-panel {
            position: absolute;
            bottom: 85px;
            left: 0;
            background: rgba(255, 255, 255, 0.95);
            border: 3px solid #8B4513;
            border-radius: 10px;
            padding: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            display: none;
            min-width: 250px;
        }
        
        .admin-panel h3 {
            color: #CC5500;
            margin: 0 0 10px 0;
            font-family: 'Georgia', serif;
            font-size: 16px;
            text-align: center;
        }
        
        .admin-panel input[type="text"],
        .admin-panel input[type="password"] {
            width: 100%;
            padding: 8px;
            margin: 5px 0;
            border: 2px solid #8B4513;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .admin-panel .button {
            background: #CC5500;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin-top: 10px;
        }
        
        .admin-panel .button:hover {
            background: #AA4400;
        }
        
        /* Hide WordPress logo */
        .login h1 a {
            display: none !important;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .portal-button {
                max-width: 250px;
            }
            
            .gnome-toggle {
                width: 60px;
            }
            
            .admin-panel {
                min-width: 200px;
            }
        }

        /* =========  VORTEX EFFECT  ========= */
        /* Background clone that we can animate */
        .vortex-background {
            animation: background-vortex 2s ease-in forwards !important;
        }
        
        /* -- selector fixed to apply to the actual <body class="login"> element -- */
        body.login.vortex-animation {
            position: relative;
            overflow: hidden;
        }
        
        body.login.vortex-animation::before {      /* pseudo water overlay */
            content: '';
            position: fixed;
            inset: 0;
            background: radial-gradient(circle at center,
                            transparent 0%,
                            transparent 30%,
                            rgba(0,100,200,.3) 60%,
                            rgba(0,150,255,.8) 100%);
            z-index: 1000;
            animation: water-overlay 2s ease-in-out forwards;
        }

        /* Keyframes for vortex animations */
        @keyframes background-vortex {
            0% {
                transform: scale(1) rotate(0deg);
                opacity: 1;
                filter: blur(0px);
            }
            25% {
                transform: scale(1.1) rotate(180deg);
                opacity: 0.9;
                filter: blur(2px);
            }
            50% {
                transform: scale(0.8) rotate(540deg);
                opacity: 0.7;
                filter: blur(4px);
            }
            75% {
                transform: scale(0.3) rotate(900deg);
                opacity: 0.4;
                filter: blur(6px);
            }
            100% {
                transform: scale(0.02) rotate(1440deg);
                opacity: 0;
                filter: blur(20px);
            }
        }
        
        @keyframes water-overlay {
            0% {
                opacity: 0;
                transform: scale(1) rotate(0deg);
                background: radial-gradient(circle at center, transparent 0%, transparent 30%, rgba(0,100,200,0.1) 60%, rgba(0,150,255,0.3) 100%);
            }
            50% {
                opacity: 0.8;
                transform: scale(1.5) rotate(180deg);
                background: radial-gradient(circle at center, transparent 0%, rgba(0,150,255,0.2) 20%, rgba(0,100,200,0.6) 50%, rgba(0,50,150,0.9) 100%);
            }
            100% {
                opacity: 1;
                transform: scale(3) rotate(720deg);
                background: radial-gradient(circle at center, rgba(0,200,255,0.8) 0%, rgba(0,100,200,0.9) 30%, rgba(0,50,150,1) 100%);
            }
        }
    </style>
    
    <!-- html2canvas for snapshot -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    
    <script type="text/javascript">
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Portal page script loaded - Phase 1');
        
        // FIRST: Replace the login form with our custom interface
        const loginDiv = document.getElementById('login');
        if (loginDiv) {
            console.log('Login div found, replacing content...');
            loginDiv.innerHTML = `
                <div class="portal-button-container">
                    <img src="<?php echo plugins_url('enterportal.png', __FILE__); ?>" 
                         alt="Enter Portal" 
                         class="portal-button" 
                         title="Click to enter the Family Portal">
                </div>
                
                <div class="gnome-container">
                    <img src="<?php echo plugins_url('gnome-stump.png', __FILE__); ?>" 
                         alt="Admin Access" 
                         class="gnome-toggle" 
                         title="Click for admin access">
                    
                    <div class="admin-panel">
                        <h3>Admin Only</h3>
                        <form method="post" action="<?php echo wp_login_url(); ?>">
                            <input type="text" name="log" placeholder="Username" required>
                            <input type="password" name="pwd" placeholder="Password" required>
                            <input type="submit" class="button" value="Login">
                            <input type="hidden" name="redirect_to" value="<?php echo admin_url(); ?>">
                        </form>
                    </div>
                </div>
            `;
            console.log('Content replaced successfully');
        } else {
            console.log('Login div NOT found!');
        }
        
        // Small delay to ensure DOM is fully updated
        setTimeout(function() {
            console.log('Portal page script loaded - Phase 2');
            
            // Gnome toggle functionality
            const gnome = document.querySelector('.gnome-toggle');
            const adminPanel = document.querySelector('.admin-panel');
            
            console.log('Gnome element:', gnome);
            console.log('Admin panel element:', adminPanel);
            
            if (gnome && adminPanel) {
                gnome.addEventListener('click', function() {
                    console.log('Gnome clicked!');
                    if (adminPanel.style.display === 'none' || adminPanel.style.display === '') {
                        adminPanel.style.display = 'block';
                        console.log('Admin panel shown');
                    } else {
                        adminPanel.style.display = 'none';
                        console.log('Admin panel hidden');
                    }
                });
            }
            
            // Portal button vortex effect
            const portalButton = document.querySelector('.portal-button');
            console.log('Portal button element:', portalButton);
            
            if (portalButton) {
                portalButton.addEventListener('click', function(e) {
                    console.log('Portal button clicked!');
                    e.preventDefault();
                    
                    // FIRST: Hide the original background and create animated clone
                    var backgroundClone = document.createElement('div');
                    backgroundClone.style.cssText = `
                        position: fixed;
                        top: 0;
                        left: 0;
                        width: 100%;
                        height: 100%;
                        background: url('<?php echo plugins_url('background.jpg', __FILE__); ?>') no-repeat center center;
                        background-size: cover;
                        z-index: 5;
                        transform-origin: center center;
                    `;
                    
                    // Hide original background and add clone
                    document.body.style.background = 'black';
                    document.body.appendChild(backgroundClone);
                    
                    // Hide gnome immediately
                    var gnomeContainer = document.querySelector('.gnome-container');
                    if (gnomeContainer) {
                        gnomeContainer.style.display = 'none';
                    }
                    
                    // THEN: trigger CSS-keyframed swirl on the clone
                    setTimeout(function() {
                        backgroundClone.classList.add('vortex-background');
                        document.body.classList.add('vortex-animation');
                    }, 50);
                    
                    // Redirect after animation
                    setTimeout(function() {
                        console.log('Starting redirect to Keycloak...');
                        
                        // Method 1: Generate direct Keycloak URL
try {
    var keycloakUrl = '<?php echo get_option("fpoidc_keycloak_url", ""); ?>/realms/<?php echo get_option("fpoidc_realm", ""); ?>/protocol/openid-connect/auth?client_id=<?php echo get_option("fpoidc_client_id", ""); ?>&redirect_uri=' + encodeURIComponent('<?php echo admin_url("admin-ajax.php?action=fpoidc_callback"); ?>') + '&response_type=code&scope=openid email profile groups&state=' + encodeURIComponent('<?php echo wp_create_nonce("fpoidc_auth_" . time()); ?>');
    console.log('Generated Keycloak URL:', keycloakUrl);
    window.location.href = keycloakUrl;
    return;
} catch(e) {
    console.log('Method 1 failed:', e);
}
                        
                        // Method 2: Use WordPress login with portal parameter
                        try {
                            console.log('Using WordPress login redirect method');
                            var loginUrl = '<?php echo wp_login_url(); ?>?portal_login=1';
                            console.log('Login URL:', loginUrl);
                            window.location.href = loginUrl;
                        } catch(e) {
                            console.log('Method 2 failed:', e);
                            // Final fallback
                            window.location.href = '<?php echo wp_login_url(); ?>';
                        }
                    }, 2000);
                });
            } else {
                console.log('Portal button not found!');
            }
        }, 100);
    });
    </script>
    <?php
}

// Handle the portal login redirect
add_action('admin_post_nopriv_family_portal_login', 'handle_family_portal_login');
add_action('admin_post_family_portal_login', 'handle_family_portal_login');
add_action('login_init', 'handle_portal_login_parameter');

function handle_portal_login_parameter() {
    if (isset($_GET['portal_login']) && $_GET['portal_login'] == '1') {
        // Redirect to the plugin's authorization URL using the same method as the original plugin
        $keycloak_url = get_option('fpoidc_keycloak_url', 'https://your_domain.com:8080');
        $realm = get_option('fpoidc_realm', 'YourRealm');
        $client_id = get_option('fpoidc_client_id', 'your-wordpress-client');
        $redirect_uri = home_url('/wp-admin/admin-ajax.php?action=fpoidc_callback');
        $state = wp_create_nonce('fpoidc_auth_' . time());
        
        // Store state in WordPress transients for validation (more reliable than sessions)
        set_transient('fpoidc_state_' . $state, $state, 600); // 10 minutes expiry
        
        $params = array(
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'openid email profile groups',
            'state' => $state
        );
        
        $auth_url = $keycloak_url . '/realms/' . $realm . '/protocol/openid-connect/auth?' . http_build_query($params);
        wp_redirect($auth_url);
        exit;
    }
}

function handle_family_portal_login() {
    // This function exists for compatibility but the main logic is in handle_portal_login_parameter
    handle_portal_login_parameter();
}
?>

<?php
/**
 * Plugin Name: Family Portal OpenID Connect
 * Plugin URI: https://github.com/Shade2074/family-portal-openid-public
 * Description: Custom OpenID Connect authentication plugin for Family Portal with Keycloak group-based role mapping. Designed specifically for self-hosted family portals with enterprise-grade single logout functionality.
 * Version: 1.1.0
 * Author: Shade2074
 * License: MIT
 * Text Domain: family-portal-openid
 * Network: false
 * 
 * This plugin provides secure OpenID Connect authentication with automatic role assignment
 * based on Keycloak group membership. Built for the Family Portal project.
 * 
 * Version 1.1.0 Features:
 * - Single logout functionality (clears both WordPress AND Keycloak sessions)
 * - Enhanced handleLogout() function with Keycloak session termination
 * - Group-based role mapping with admin privilege support
 * - Beautiful sapphire blue password toggle interface
 * - Configurable logout redirect URLs
 * - Comprehensive debugging system
 * - Professional admin interface
 * 
 * SETUP INSTRUCTIONS:
 * 1. Configure your Keycloak server with a new realm and client
 * 2. Update the plugin settings in WordPress admin
 * 3. Add the callback URL to your Keycloak client configuration
 * 4. Test the authentication flow
 * 
 * For detailed setup instructions, see: README.md
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('FPOIDC_VERSION', '1.1.0');
define('FPOIDC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('FPOIDC_PLUGIN_URL', plugin_dir_url(__FILE__));
define('FPOIDC_PLUGIN_FILE', __FILE__);

/**
 * Main Family Portal OpenID Connect Plugin Class
 */
class FamilyPortalOpenIDConnect {
    
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
        
        // Add inline script for beautiful sapphire eye toggle
        wp_add_inline_script('jquery', '
            jQuery(document).ready(function($) {
                // Add password toggle button with sapphire blue styling
                var $secretField = $("input[name=\'fpoidc_client_secret\']");
                if ($secretField.length) {
                    // Wrap field in relative container
                    $secretField.wrap("<div style=\'position: relative; display: inline-block;\'></div>");
                    
                    // Add sapphire blue eye button right after the field
                    $secretField.after("<button type=\'button\' id=\'toggle-secret\' style=\'position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 18px; color: #0066CC; transition: color 0.3s ease;\'>🙈</button>");
                    
                    // Toggle functionality with eye state changes
                    $("#toggle-secret").on("click", function() {
                        var $this = $(this);
                        var type = $secretField.attr("type") === "password" ? "text" : "password";
                        
                        $secretField.attr("type", type);
                        
                        if (type === "password") {
                            // Hidden: closed eye (sapphire blue)
                            $this.html("🙈").css("color", "#0066CC");
                        } else {
                            // Visible: open eye (brighter sapphire)
                            $this.html("👁️").css("color", "#0088FF");
                        }
                    });
                    
                    // Hover effects for better UX
                    $("#toggle-secret").hover(
                        function() { $(this).css("color", "#004499"); },
                        function() { 
                            var isVisible = $secretField.attr("type") === "text";
                            $(this).css("color", isVisible ? "#0088FF" : "#0066CC"); 
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
                            <input type="url" name="fpoidc_keycloak_url" value="<?php echo esc_attr(get_option('fpoidc_keycloak_url', 'http://YOUR_SERVER_IP:8080')); ?>" class="regular-text" />
                            <p class="description">Base URL of your Keycloak server (e.g., http://192.168.1.70:8080)</p>
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
                            <input type="text" name="fpoidc_client_id" value="<?php echo esc_attr(get_option('fpoidc_client_id', 'wordpress-client')); ?>" class="regular-text" />
                            <p class="description">OpenID Connect client ID</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Client Secret</th>
                        <td>
                            <input type="password" name="fpoidc_client_secret" value="<?php echo esc_attr(get_option('fpoidc_client_secret')); ?>" class="regular-text" />
                            <p class="description">OpenID Connect client secret (stored securely) - Click the sapphire eye to reveal/hide</p>
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
                            <input type="url" name="fpoidc_logout_redirect_url" value="<?php echo esc_attr(get_option('fpoidc_logout_redirect_url', home_url('/'))); ?>" class="regular-text" />
                            <p class="description">Where users should be redirected after logout (defaults to your home page)</p>
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
            <p><strong>Logout Redirect:</strong> <?php echo esc_html(get_option('fpoidc_logout_redirect_url', home_url('/'))); ?></p>
            <p><strong>Single Logout:</strong> <span style="color: green;">✅ Enabled (v1.1.0 feature)</span></p>
            
            <h2>Callback URLs for Keycloak Configuration</h2>
            <p><strong>Redirect URI:</strong><br>
            <code><?php echo home_url('/wp-admin/admin-ajax.php?action=fpoidc_callback'); ?></code></p>
            <p><strong>Post Logout Redirect URI:</strong><br>
            <code><?php echo esc_html(get_option('fpoidc_logout_redirect_url', home_url('/'))); ?></code></p>
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
        
        // Store state in session for validation
        if (!session_id()) {
            session_start();
        }
        $_SESSION['fpoidc_state'] = $state;
        
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
        
        // Verify state parameter
        if (!session_id()) {
            session_start();
        }
        
        $received_state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        $stored_state = isset($_SESSION['fpoidc_state']) ? $_SESSION['fpoidc_state'] : '';
        
        $this->debugLog('State verification - Received: ' . $received_state . ', Stored: ' . $stored_state);
        
        if (empty($received_state) || empty($stored_state) || $received_state !== $stored_state) {
            $this->debugLog('State parameter mismatch or missing');
            wp_die('Invalid or missing state parameter. Authentication failed for security reasons.');
        }
        
        // Clear the state
        unset($_SESSION['fpoidc_state']);
        
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
        $logout_redirect_url = get_option('fpoidc_logout_redirect_url', home_url('/'));
        
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
                'client_id' => get_option('fpoidc_client_id', 'wordpress-client')
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
        // Set default options with placeholder values
        if (!get_option('fpoidc_keycloak_url')) {
            update_option('fpoidc_keycloak_url', 'http://YOUR_SERVER_IP:8080');
        }
        if (!get_option('fpoidc_realm')) {
            update_option('fpoidc_realm', 'YourRealm');
        }
        if (!get_option('fpoidc_client_id')) {
            update_option('fpoidc_client_id', 'wordpress-client');
        }
        if (!get_option('fpoidc_admin_group')) {
            update_option('fpoidc_admin_group', 'Admin');
        }
        if (!get_option('fpoidc_default_role')) {
            update_option('fpoidc_default_role', 'subscriber');
        }
        if (!get_option('fpoidc_logout_redirect_url')) {
            update_option('fpoidc_logout_redirect_url', home_url('/'));
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
FamilyPortalOpenIDConnect::getInstance();

?>

# Family Portal OpenID Connect

**Enterprise-grade OpenID Connect authentication plugin for WordPress with Keycloak integration**

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/Shade2074/family-portal-openid-public)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue.svg)](https://php.net/)

## 🚀 Features

- **🔐 Single Logout** - Enterprise-grade logout that clears both WordPress AND Keycloak sessions
- **👥 Group-Based Role Mapping** - Automatic WordPress role assignment based on Keycloak groups
- **💎 Beautiful UI** - Sapphire blue password toggle and professional admin interface
- **🛡️ Security First** - Comprehensive state validation and secure token handling
- **📊 Debug Mode** - Detailed logging for troubleshooting authentication flows
- **⚙️ Configurable** - Flexible logout redirects and role mappings
- **🏢 Self-Hosted** - Perfect for family portals and private organizations

## 📋 Requirements

- WordPress 6.0+
- PHP 7.4+
- Keycloak 15.0+ server
- SSL recommended for production

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   WordPress     │◄──►│   This Plugin    │◄──►│   Keycloak      │
│   (Your Site)   │    │   (OIDC Bridge)  │    │   (Auth Server) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

This plugin acts as an OpenID Connect bridge between your WordPress site and Keycloak authentication server, providing secure single sign-on with group-based permissions.

## 🚀 Quick Start

### Step 1: Install the Plugin

1. Download the plugin files
2. Upload to `/wp-content/plugins/family-portal-openid/`
3. Activate through WordPress admin
4. Go to **Settings** → **Family Portal Auth**

### Step 2: Configure Keycloak

1. **Create a new Realm** (e.g., "FamilyPortal")
2. **Create a new Client**:
   - Client ID: `wordpress-client`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: `https://your-site.com/wp-admin/admin-ajax.php?action=fpoidc_callback`
   - Valid Post Logout Redirect URIs: `https://your-site.com/`
3. **Create Groups** (e.g., "Admin", "Family", "Guest")
4. **Add Group Membership Mapper**:
   - Name: `Group Membership`
   - Mapper Type: `Group Membership`
   - Token Claim Name: `groups`
   - Add to ID token: ON
   - Add to access token: ON
   - Add to userinfo: ON

### Step 3: Configure WordPress Plugin

Fill in the plugin settings:

```
Keycloak Server URL: http://your-keycloak-server:8080
Realm: FamilyPortal
Client ID: wordpress-client
Client Secret: [your-client-secret]
Admin Group Name: Admin
Default Role: subscriber
Logout Redirect URL: https://your-site.com/
```

### Step 4: Test Authentication

1. Go to your WordPress login page
2. Click "🔐 Login with Family Portal"
3. Login with your Keycloak credentials
4. Verify you're logged into WordPress with correct role

## ⚙️ Configuration Options

### WordPress Plugin Settings

| Setting | Description | Example |
|---------|-------------|---------|
| **Keycloak Server URL** | Base URL of your Keycloak instance | `http://192.168.1.70:8080` |
| **Realm** | Keycloak realm name | `FamilyPortal` |
| **Client ID** | OpenID Connect client identifier | `wordpress-client` |
| **Client Secret** | Client secret from Keycloak | `abc123...` |
| **Admin Group Name** | Keycloak group for WordPress admins | `Admin` |
| **Default Role** | Default role for new users | `subscriber` |
| **Logout Redirect URL** | Where to redirect after logout | `https://your-site.com/` |
| **Debug Mode** | Enable detailed logging | `☑️ Enabled` |

### Keycloak Client Configuration

**Required Client Settings:**
```
Client ID: wordpress-client
Access Type: confidential
Standard Flow Enabled: ON
Direct Access Grants Enabled: OFF
Valid Redirect URIs: https://your-site.com/wp-admin/admin-ajax.php?action=fpoidc_callback
Valid Post Logout Redirect URIs: https://your-site.com/*
```

**Required Mappers:**
1. **Group Membership Mapper**
   - Token Claim Name: `groups`
   - Full group path: OFF
   - Add to userinfo: ON

## 🛡️ Security Features

### Single Logout (v1.1.0+)
The plugin implements enterprise-grade single logout:
1. User clicks "Logout" in WordPress
2. Plugin redirects to Keycloak logout endpoint
3. Keycloak terminates its session
4. User is redirected back to your specified URL
5. Both WordPress AND Keycloak sessions are cleared

### State Parameter Validation
- Generates cryptographic nonces for each authentication request
- Validates state parameters to prevent CSRF attacks
- Session-based state storage with automatic cleanup

### Secure Token Handling
- Client secrets are stored securely in WordPress options
- Access tokens are never logged or stored permanently
- Comprehensive error handling with user-friendly messages

## 🎨 User Experience Features

### Beautiful Login Interface
- Professional "🔐 Login with Family Portal" button
- Seamless integration with WordPress login page
- Clear user messaging and error handling

### Sapphire Blue Admin Interface
- Beautiful password toggle with sapphire blue styling
- Intuitive configuration interface
- Real-time status indicators

### Smart Role Mapping
```php
// Example: Multi-tier family access
Admin Group    → WordPress Administrator
Parent Group   → WordPress Editor  
Family Group   → WordPress Author
Guest Group    → WordPress Subscriber
```

## 🔧 Troubleshooting

### Common Issues

**1. "Invalid redirect uri" error**
- Check that your Redirect URI in Keycloak exactly matches: `https://your-site.com/wp-admin/admin-ajax.php?action=fpoidc_callback`
- Ensure no trailing slashes or extra characters

**2. "Missing parameters: id_token_hint" error**
- Add your logout redirect URL to "Valid Post Logout Redirect URIs" in Keycloak
- Verify the client_id parameter is correctly configured

**3. Groups not working**
- Ensure the "Group Membership" mapper is configured in Keycloak
- Check that "Add to userinfo" is enabled for the groups mapper
- Verify users are assigned to the correct groups

**4. Debug Mode**
Enable debug mode in plugin settings to see detailed logs:
```bash
tail -f /path/to/wordpress/wp-content/debug.log
```

### Debug Information

When debug mode is enabled, you'll see detailed logs like:
```
[Family Portal OpenID] Generated authorization URL: http://keycloak:8080/realms/...
[Family Portal OpenID] Token exchange successful
[Family Portal OpenID] User info retrieved: {"sub":"user123","email":"user@example.com","groups":["Admin"]}
[Family Portal OpenID] Assigned administrator role to user (in group: Admin)
[Family Portal OpenID] User logout initiated - implementing single logout
```

## 🚧 Advanced Configuration

### Custom Scopes
The plugin requests these OpenID Connect scopes:
- `openid` - Basic OpenID Connect
- `email` - User email address
- `profile` - User profile information
- `groups` - Group membership information

### Multi-Environment Setup
For development/staging/production environments:

```php
// Development
update_option('fpoidc_keycloak_url', 'http://localhost:8080');
update_option('fpoidc_realm', 'dev-realm');

// Production
update_option('fpoidc_keycloak_url', 'https://auth.yourfamily.com');
update_option('fpoidc_realm', 'production-realm');
```

### Custom Role Mapping
```php
// Example: Custom role logic in functions.php
add_filter('fpoidc_user_role', function($role, $groups, $user_info) {
    if (in_array('PowerUser', $groups)) {
        return 'editor';
    }
    if (in_array('ReadOnly', $groups)) {
        return 'subscriber';
    }
    return $role;
}, 10, 3);
```

## 📚 API Reference

### Hooks and Filters

**Actions:**
- `fpoidc_user_created` - Fired when a new user is created
- `fpoidc_user_updated` - Fired when an existing user is updated
- `fpoidc_login_success` - Fired after successful login

**Filters:**
- `fpoidc_user_role` - Customize role assignment logic
- `fpoidc_login_redirect` - Customize post-login redirect
- `fpoidc_logout_redirect` - Customize post-logout redirect

### Plugin Constants

```php
FPOIDC_VERSION       // Plugin version
FPOIDC_PLUGIN_DIR    // Plugin directory path
FPOIDC_PLUGIN_URL    // Plugin URL
```

## 🔄 Version History

### v1.1.0 (Current)
- ✅ **NEW:** Single logout functionality (clears both WordPress AND Keycloak sessions)
- ✅ **NEW:** Enhanced handleLogout() function with Keycloak session termination
- ✅ **NEW:** Client ID parameter for improved Keycloak compatibility
- ✅ Configurable logout redirect URLs
- ✅ Improved debugging and error handling

### v1.0.4
- ✅ Configurable logout redirect URL setting
- ✅ Enhanced admin interface with logout behavior control
- ✅ Improved debugging with logout behavior logging

### v1.0.3
- ✅ Fixed critical syntax errors in handleLogout function
- ✅ Cleaned up commented code and extra braces
- ✅ Stabilized core authentication functionality

### v1.0.2
- ✅ Enhanced authentication with sapphire eye icon
- ✅ Added beautiful password toggle with proper positioning
- ✅ Implemented groups scope for Keycloak integration
- ✅ Fixed group mapper configuration for admin privileges

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Shade2074/family-portal-openid-public.git

# Install in WordPress
cp -r family-portal-openid-public /path/to/wordpress/wp-content/plugins/

# Enable WordPress debug mode
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Keycloak Community** - For the excellent open-source identity management platform
- **WordPress Community** - For the robust plugin architecture
- **OpenID Connect Working Group** - For the secure authentication standards
- **Family Portal Project** - For inspiring this community-focused authentication solution

## 📞 Support

- **Documentation**: See this README and inline code comments
- **Issues**: [GitHub Issues](https://github.com/Shade2074/family-portal-openid-public/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Shade2074/family-portal-openid-public/discussions)

## 🌟 Star History

If this plugin helped you secure your family portal, please consider giving it a star! ⭐

---

**Built with ❤️ for families who want secure, self-hosted authentication solutions.**

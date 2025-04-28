package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
)

const (
	PluginVersion               = "0.1.0"
	PluginPriority              = 1000 // Run before authentication plugins
	DefaultTurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	DefaultTimeoutMs          = 5000 // 5 seconds
	DefaultTokenHeader        = "Cf-Turnstile-Response" // Common header for Turnstile token
	DefaultRemoteIPHeader     = "X-Forwarded-For"      // Common header for client IP
)

// --- Configuration Struct ---
// Holds the configuration parameters defined in Kong's config (kong.conf or CRD)
type Config struct {
	TurnstileSecretKey string `json:"turnstile_secret_key"`       // REQUIRED: Your Cloudflare Turnstile Secret Key
	TurnstileVerifyURL string `json:"turnstile_verify_url"`       // Optional: Override default verification URL
	TokenLocation      string `json:"token_location"`             // Optional: Where to find the token ('header', 'form'). Default: 'header'
	TokenName          string `json:"token_name"`                 // Optional: Name of header or form field. Default: 'Cf-Turnstile-Response'
	RemoteIPLocation   string `json:"remote_ip_location"`       // Optional: Where to find client IP ('header', 'pdk'). Default: 'pdk'
	RemoteIPName       string `json:"remote_ip_name"`           // Optional: Header name if location is 'header'. Default: 'X-Forwarded-For'
	RequestTimeoutMs   int    `json:"request_timeout_ms"`       // Optional: Timeout for Cloudflare API call. Default: 5000ms
}

// --- Cloudflare SiteVerify Response Struct ---
type SiteVerifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTs string   `json:"challenge_ts"` // Timestamp of the challenge load (ISO format yyyy-MM-ddTHH:mm:ssZZ)
	Hostname    string   `json:"hostname"`     // Hostname of site where challenge was solved
	ErrorCodes  []string `json:"error-codes"`  // Optional error codes
	Action      string   `json:"action"`       // Optional: Customer widget identifier passed to the widget on the client side
	CData       string   `json:"cdata"`        // Optional: Customer data passed to the widget on the client side
}

// --- Kong Plugin Constructor ---
func New() interface{} {
	return &Config{}
}

// --- Plugin Implementation ---

// Access phase: This is where we intercept the request *before* it hits the upstream service.
func (conf Config) Access(kong *pdk.PDK) {
	kong.Log.Info("Turnstile Plugin: Starting Access Phase")

	// --- Validate Configuration ---
	if conf.TurnstileSecretKey == "" {
		kong.Log.Err("Turnstile configuration error: turnstile_secret_key is required")
		kong.Response.Exit(http.StatusInternalServerError, []byte("Plugin Configuration Error"), nil)
		return
	}

	// --- Get Turnstile Token ---
	tokenLocation := strings.ToLower(conf.TokenLocation)
	if tokenLocation == "" {
		tokenLocation = "header" // Default to header
	}
	tokenName := conf.TokenName
	if tokenName == "" {
		tokenName = DefaultTokenHeader // Default header name
	}

	var turnstileToken string
	var err error

	switch tokenLocation {
	case "header":
		turnstileToken, err = kong.Request.GetHeader(tokenName)
		if err != nil {
			kong.Log.Err(fmt.Sprintf("Error getting Turnstile token from header '%s': %v", tokenName, err))
			kong.Response.Exit(http.StatusBadRequest, []byte("Turnstile token missing or invalid"), nil)
			return
		}
	case "form":
		formArgs, err := kong.Request.GetForm()
		if err != nil {
			kong.Log.Err(fmt.Sprintf("Error getting form arguments: %v", err))
			kong.Response.Exit(http.StatusBadRequest, []byte("Could not read form data"), nil)
			return
		}
		tokenValues, ok := formArgs[tokenName]
		if !ok || len(tokenValues) == 0 {
			kong.Log.Warn(fmt.Sprintf("Turnstile token not found in form field '%s'", tokenName))
			kong.Response.Exit(http.StatusBadRequest, []byte("Turnstile token missing"), nil)
			return
		}
		turnstileToken = tokenValues[0] // Use the first value if multiple exist
	default:
		kong.Log.Err(fmt.Sprintf("Invalid token_location configured: '%s'. Use 'header' or 'form'.", conf.TokenLocation))
		kong.Response.Exit(http.StatusInternalServerError, []byte("Plugin Configuration Error"), nil)
		return
	}

	if turnstileToken == "" {
		kong.Log.Warn("Turnstile token is empty")
		kong.Response.Exit(http.StatusBadRequest, []byte("Turnstile token missing"), nil)
		return
	}

	// --- Get Client IP Address ---
	remoteIPLocation := strings.ToLower(conf.RemoteIPLocation)
	if remoteIPLocation == "" {
		remoteIPLocation = "pdk" // Default to PDK
	}
	remoteIPName := conf.RemoteIPName
	if remoteIPName == "" {
		remoteIPName = DefaultRemoteIPHeader
	}
	var clientIP string

	switch remoteIPLocation {
	case "pdk":
		clientIP, err = kong.Request.GetForwardedIp() // Recommended PDK function
		if err != nil || clientIP == "" {
			// Fallback if GetForwardedIp fails
			clientIP, err = kong.Request.GetClientIp()
			if err != nil {
				kong.Log.Warn(fmt.Sprintf("Could not get client IP using PDK: %v", err))
				// Optionally proceed without IP if Cloudflare doesn't require it strictly
			}
		}
	case "header":
		clientIP, err = kong.Request.GetHeader(remoteIPName)
		if err != nil {
			kong.Log.Warn(fmt.Sprintf("Could not get client IP from header '%s': %v", remoteIPName, err))
			// Optionally proceed without IP
		}
		// Often headers like X-Forwarded-For contain a list, take the first one
		if strings.Contains(clientIP, ",") {
			clientIP = strings.TrimSpace(strings.Split(clientIP, ",")[0])
		}
	default:
		kong.Log.Warn(fmt.Sprintf("Invalid remote_ip_location configured: '%s'. Use 'pdk' or 'header'. Proceeding without remote IP.", conf.RemoteIPLocation))
	}

	kong.Log.Info(fmt.Sprintf("Verifying Turnstile token for IP: %s", clientIP))

	// --- Call Cloudflare SiteVerify API ---
	verifyURL := conf.TurnstileVerifyURL
	if verifyURL == "" {
		verifyURL = DefaultTurnstileVerifyURL
	}
	timeout := time.Duration(DefaultTimeoutMs) * time.Millisecond
	if conf.RequestTimeoutMs > 0 {
		timeout = time.Duration(conf.RequestTimeoutMs) * time.Millisecond
	}

	httpClient := &http.Client{Timeout: timeout}

	// Prepare form data
	formData := url.Values{}
	formData.Set("secret", conf.TurnstileSecretKey)
	formData.Set("response", turnstileToken)
	if clientIP != "" {
		formData.Set("remoteip", clientIP)
	}

	reqBody := bytes.NewBufferString(formData.Encode())

	req, err := http.NewRequest("POST", verifyURL, reqBody)
	if err != nil {
		kong.Log.Err(fmt.Sprintf("Failed to create request to Cloudflare: %v", err))
		kong.Response.Exit(http.StatusInternalServerError, []byte("Turnstile verification failed (request creation)"), nil)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		kong.Log.Err(fmt.Sprintf("Failed to call Cloudflare verification API: %v", err))
		kong.Response.Exit(http.StatusBadGateway, []byte("Turnstile verification failed (connection error)"), nil)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		kong.Log.Err(fmt.Sprintf("Failed to read Cloudflare response body: %v", err))
		kong.Response.Exit(http.StatusInternalServerError, []byte("Turnstile verification failed (read error)"), nil)
		return
	}

	if resp.StatusCode != http.StatusOK {
		kong.Log.Err(fmt.Sprintf("Cloudflare API returned non-200 status: %d - Body: %s", resp.StatusCode, string(bodyBytes)))
		kong.Response.Exit(http.StatusBadGateway, []byte("Turnstile verification failed (API error)"), nil)
		return
	}

	// --- Parse Cloudflare Response ---
	var verifyResponse SiteVerifyResponse
	err = json.Unmarshal(bodyBytes, &verifyResponse)
	if err != nil {
		kong.Log.Err(fmt.Sprintf("Failed to parse Cloudflare JSON response: %v - Body: %s", err, string(bodyBytes)))
		kong.Response.Exit(http.StatusInternalServerError, []byte("Turnstile verification failed (parse error)"), nil)
		return
	}

	// --- Make Decision ---
	if verifyResponse.Success {
		kong.Log.Info("Turnstile verification successful!")
		// Optional: Set headers with verification details if needed by upstream
		// kong.ServiceRequest.SetHeader("X-Turnstile-Verified", "true")
		// kong.ServiceRequest.SetHeader("X-Turnstile-Hostname", verifyResponse.Hostname)
	} else {
		errorCodes := strings.Join(verifyResponse.ErrorCodes, ", ")
		kong.Log.Warn(fmt.Sprintf("Turnstile verification failed. Error codes: [%s]", errorCodes))
		// Provide a more generic error to the client for security
		kong.Response.Exit(http.StatusForbidden, []byte("Verification failed"), nil)
	}
}

// --- Main function to run the plugin server ---
func main() {
	server.StartServer(New, PluginVersion, PluginPriority)
}


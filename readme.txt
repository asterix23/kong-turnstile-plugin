You need the go-pluginserver binary from Kong.
Configure Kong to use the Go plugin server and point it to your plugin binary. This involves setting environment variables like KONG_PLUGINS, KONG_PLUGINSERVER_NAMES, KONG_PLUGINSERVER_GO_PLUGIN_PATH, etc. Refer to the official Kong Go Plugin documentation for detailed deployment steps.
Important Considerations:
Secret Management: Never hardcode your turnstile_secret_key directly in configuration files, especially in version control. Use environment variables or Kong's secret management capabilities (like Vault integration or Kubernetes secrets).
Error Handling: The example provides basic error handling. You might want more sophisticated logging or specific responses based on Cloudflare error codes.
Performance: Calling an external API for every request adds latency. Consider if this verification is needed on all routes or only specific sensitive ones.
Client-Side Implementation: This plugin assumes the client-side Turnstile widget has been implemented correctly and is sending the token in the configured location (e.g., the Cf-Turnstile-Response header).

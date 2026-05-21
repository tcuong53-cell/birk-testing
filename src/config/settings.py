import os
import urllib.parse
import ipaddress

# Base URL for Polar.sh services and API.
# This value should be configurable via an environment variable (POLAR_BASE_URL)
# to allow for different deployments (development, staging, production).
# It defaults to the official production URL (https://polar.sh)
# to prevent accidental exposure of local development endpoints in public content
# (e.g., GitHub issue badges) and to mitigate Server-Side Request Forgery (SSRF) risks
# by validating the URL against internal/loopback addresses as per security guidelines.

DEFAULT_POLAR_BASE_URL = "https://polar.sh"

def _is_private_ip(ip_str: str) -> bool:
    """
    Checks if an IP address string belongs to a private or loopback range.
    This helper function is used for URL validation against potential SSRF vulnerabilities,
    adhering to BOUNTY_HUNTER_MASTER_RULES.md Chapter III.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:  # Covers 127.0.0.0/8 (IPv4) and ::1/128 (IPv6)
            return True
        if ip_obj.is_private:  # Covers RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) for IPv4
                               # and Unique Local Addresses (fc00::/7) for IPv6
            return True
        # Explicitly check 0.0.0.0, which is often used as a wildcard for all interfaces
        if ip_obj == ipaddress.ip_address("0.0.0.0"):
            return True
        return False
    except ValueError:
        # Not a valid IP address string, so it's not a private IP in this context
        return False

def _is_potentially_internal_url(url: str) -> bool:
    """
    Checks if a URL's hostname explicitly refers to an internal or loopback resource.
    This validation helps prevent SSRF by disallowing direct configuration of internal
    endpoints in POLAR_BASE_URL. It prioritizes checking the hostname string itself
    over active DNS resolution to avoid network calls during module loading.
    Adheres to BOUNTY_HUNTER_MASTER_RULES.md Chapter III: Anti-SSRF.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            # If no hostname (e.g., relative path, or malformed URL that fails to parse hostname),
            # it is safer to treat this as an invalid configuration that could pose a risk,
            # especially since POLAR_BASE_URL is expected to be a full, absolute URL.
            return True

        # Check for common internal hostnames (case-insensitive)
        if hostname.lower() in ("localhost", "0.0.0.0"):
            return True

        # Check if the hostname is an IP address and if it's a private/loopback IP
        if _is_private_ip(hostname):
            return True

        return False
    except Exception:
        # Catch any unexpected errors during URL parsing.
        # It's always safer to treat malformed or unparsable URLs as potentially internal
        # to prevent unforeseen risks.
        return True


# Attempt to get the URL from the environment variable POLAR_BASE_URL.
configured_polar_base_url = os.environ.get("POLAR_BASE_URL")

# Validate the configured URL if it exists.
if configured_polar_base_url:
    if _is_potentially_internal_url(configured_polar_base_url):
        # If the configured URL points to an internal resource (localhost, private IP),
        # revert to the default public URL for security reasons (SSRF prevention).
        # A warning would typically be logged here in a production system.
        POLAR_BASE_URL = DEFAULT_POLAR_BASE_URL
    else:
        # If the configured URL is valid and not internal, use it.
        POLAR_BASE_URL = configured_polar_base_url
else:
    # If the environment variable POLAR_BASE_URL is not set, use the default public URL.
    POLAR_BASE_URL = DEFAULT_POLAR_BASE_URL
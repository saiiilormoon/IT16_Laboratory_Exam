<?php
// ============================================
// SECURITY HEADERS
// Applied to all pages for defense-in-depth
// ============================================

// Prevent clickjacking
header("X-Frame-Options: DENY");

// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");

// Enable XSS protection in older browsers
header("X-XSS-Protection: 1; mode=block");

// Referrer policy - don't leak full URL
header("Referrer-Policy: strict-origin-when-cross-origin");

// Permissions policy - restrict browser features
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");

// Content-Security-Policy - restrict resource loading
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';");

// Cache control for sensitive pages
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
?>

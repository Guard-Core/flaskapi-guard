---

title: Proxy Security - FlaskAPI Guard
description: Secure handling of X-Forwarded-For headers and proxy configurations in FlaskAPI Guard
keywords: proxy security, X-Forwarded-For, header security, IP spoofing prevention
---

Proxy Security
==============

When your application is behind a proxy, load balancer, or CDN, properly handling the `X-Forwarded-For` header is critical for security. FlaskAPI Guard implements a secure approach to prevent IP spoofing attacks.

___

The Problem
-----------

The `X-Forwarded-For` header is sent by proxies to identify the original client IP, but since it can be manipulated by clients, it poses a security risk if trusted blindly.

Common security issues include:

- IP spoofing to bypass IP-based access controls
- False attribution in security logs
- Bypassing rate limiting and IP bans

___

Secure Configuration
--------------------

FlaskAPI Guard implements a secure-by-default approach where X-Forwarded-For headers are only trusted from explicitly configured trusted proxies:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs/ranges
    trusted_proxy_depth=1,  # Number of proxies in the chain (default: 1)
    trust_x_forwarded_proto=True,  # Whether to trust X-Forwarded-Proto for HTTPS detection
)
```

___

How It Works
------------

1. When a request arrives, FlaskAPI Guard checks if it's from a trusted proxy
2. If not from a trusted proxy, the direct connecting IP is always used
3. If from a trusted proxy, the X-Forwarded-For header is parsed to extract the original client IP
4. The extracted IP is then used for all security checks

___

Prerequisite: Do Not Pre-Resolve the Client with ProxyFix
---------------------------------------------------------

FlaskAPI Guard reads the connecting IP from `request.remote_addr`. Werkzeug's `ProxyFix` middleware sets `REMOTE_ADDR` from the `X-Forwarded-For` header before your Flask app (and so FlaskAPI Guard) runs: with `x_for` greater than 0 it takes the value `x_for` positions from the right of the header and assigns it to `REMOTE_ADDR`, and it leaves the real peer unchanged only when the header has fewer values than `x_for`.

!!! warning "ProxyFix and `trusted_proxies` must not both resolve the client"
    When `ProxyFix(app.wsgi_app, x_for=1)` wraps the app and the app server is reachable by clients directly, a client sends its own `X-Forwarded-For` and `ProxyFix` makes that value the connecting IP, so a client can pick a new identity on every request and rate limits and bans stop working. Choose one authority: either remove `x_for` from `ProxyFix` (`x_for=0`) and let `trusted_proxies` and `trusted_proxy_depth` resolve the client, or keep `ProxyFix` and make sure the app server only accepts connections from the proxies that append the header, with `x_for` equal to the number of those proxies. Do not configure both for the same hops.

The same applies to the WSGI server in front of Flask. Gunicorn does not rewrite `REMOTE_ADDR` from `X-Forwarded-For` (its `forwarded_allow_ips` only governs the scheme and forwarder headers), so it needs no change.

___

Configuration Options
---------------------

trusted_proxies
---------------

List of IP addresses or CIDR ranges that are allowed to set X-Forwarded-For headers:

```python
config = SecurityConfig(
    trusted_proxies=[
        "10.0.0.1",  # Single IP
        "192.168.1.0/24",  # CIDR range
        "172.16.0.0/16",  # Another CIDR range
    ]
)
```

If empty (default), X-Forwarded-For headers will not be trusted at all.

trusted_proxy_depth
-------------------

Controls how the client IP is extracted from the X-Forwarded-For header:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1"],
    trusted_proxy_depth=2,  # Assumes two proxies in the chain
)
```

The X-Forwarded-For format is: `client, proxy1, proxy2, ...` (leftmost is the original client)

- With depth=1 (default): Assumes one proxy in chain, uses leftmost IP as client
- With depth=2: Assumes two proxies in chain, still uses leftmost IP
- Higher values handle more complex proxy chains

trust_x_forwarded_proto
-----------------------

Whether to trust the X-Forwarded-Proto header for HTTPS detection:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1"],
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto from trusted proxies
)
```

This only applies when the request comes from a trusted proxy.

___

Real-World Examples
-------------------

Single Reverse Proxy
---------------------

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1"],  # Your Nginx/HAProxy IP
    trusted_proxy_depth=1,  # One proxy
    trust_x_forwarded_proto=True,  # Trust HTTPS status from proxy
)
```

Load Balancer + Proxy
---------------------

```python
config = SecurityConfig(
    trusted_proxies=[
        "10.0.0.1",  # Load balancer IP
        "192.168.1.0/24",  # Internal proxy subnet
    ],
    trusted_proxy_depth=2,  # Two proxies in chain
    trust_x_forwarded_proto=True,
)
```

Cloud Provider Load Balancer
-----------------------------

```python
config = SecurityConfig(
    trusted_proxies=[
        "10.0.0.0/8"  # Cloud provider's internal IP range
    ],
    trusted_proxy_depth=1,
    trust_x_forwarded_proto=True,
)
```

___

Best Practices
--------------

1. **Be specific**: Only include the exact IPs or ranges of your known proxies
2. **Use correct depth**: Configure based on your actual proxy chain
3. **Regular audits**: Periodically review your trusted proxy list
4. **Test configuration**: Verify correct IP extraction in your environment

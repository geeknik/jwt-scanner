# JWT Algorithm Confusion Scanner

A specialized security tool for detecting JWT algorithm confusion vulnerabilities in web applications, allowing penetration testers to identify improper token validation techniques that can lead to authentication bypasses.

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

### Options

```
usage: jwt_scanner.py [-h] [-t TOKEN] [-c COOKIE] [-a] [-k PUBLIC_KEY] [-p PAYLOAD] [-v] [-d DELAY] url

JWT Algorithm Confusion Scanner

positional arguments:
  url                   Target URL to test

optional arguments:
  -h, --help            show this help message and exit
  -t, --token TOKEN     JWT token to test
  -c, --cookie COOKIE   Name of the cookie containing the JWT
  -a, --auth-header     Use Authorization header
  -k, --public-key      Path to public key file
  -v, --verbose         Enable verbose output
  -d, --delay DELAY     Delay between requests (seconds)
  -p, --payload         Path to custom payload JSON file
```

## Features

1. **Automatic token extraction** - Detects JWTs in cookies or authorization headers
2. **Multiple attack vectors** - Tests common JWT flaws in a single run
3. **Response analysis** - Attempts to determine if attacks were successful
4. **Public key exploitation** - Tests for signature bypasses using public key confusion
5. **Custom payload support** - Test with your own JWT manipulation techniques

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

## Example Output

```
[+] Starting JWT Algorithm Confusion Scanner
[*] Target URL: https://vulnerable-site.com
[+] Found JWT in cookie: session
[+] Successfully decoded JWT token

[*] Testing for 'none' algorithm vulnerability...
[*] Trying alg-none: Algorithm set to 'none' with empty signature
[+] Potential vulnerability found! Attack: alg-none
[+] Vulnerable token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.

[*] Testing for key confusion vulnerability...
[*] Trying key-confusion: Switched from RS256 to HS256 using public key as HMAC secret
[+] Got non-error status code: 200
[+] Possible success indicator found: 'admin'
[+] Potential vulnerability found! Attack: key-confusion
[+] Vulnerable token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.a77Bn8Vxe7YRzOZ9Ao0j4J4pRwIwNql7Z5x98QPXIoc

...

[!] Target appears VULNERABLE to JWT algorithm confusion attacks!
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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

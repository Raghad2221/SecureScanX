import google.generativeai as genai
import time
import re

# Configure Gemini API
API_KEY = "AIzaSyB-8BfcF54ZxSaYLiWGNkS5X-847IyQDWY"
genai.configure(api_key=API_KEY)

# Use the free-tier Gemini model
model = genai.GenerativeModel('gemini-2.0-flash-exp')

# Rate limiting to conserve API credits
last_call_time = 0
MIN_CALL_INTERVAL = 2  # Minimum 2 seconds between calls (increased from 1)
MAX_RETRIES = 3  # Maximum retry attempts for rate limit errors

def get_mitigation(vulnerability_name, retry_count=0):
    """
    Get a brief mitigation advice (10-15 words) for a vulnerability using Gemini API.

    Args:
        vulnerability_name (str): Name of the vulnerability
        retry_count (int): Current retry attempt

    Returns:
        str: Brief mitigation advice (10-15 words)
    """
    global last_call_time

    try:
        # Rate limiting
        current_time = time.time()
        time_since_last_call = current_time - last_call_time
        if time_since_last_call < MIN_CALL_INTERVAL:
            time.sleep(MIN_CALL_INTERVAL - time_since_last_call)

        # Create a concise prompt to minimize token usage
        prompt = f"How to fix {vulnerability_name}? Answer in 10-15 words only:"

        # Generate content
        response = model.generate_content(prompt)
        last_call_time = time.time()

        # Extract and return the text
        mitigation_text = response.text.strip()

        # Limit to approximately 15 words if response is too long
        words = mitigation_text.split()
        if len(words) > 20:
            mitigation_text = ' '.join(words[:15]) + '...'

        return mitigation_text

    except Exception as e:
        error_str = str(e)
        print(f"Gemini API error for {vulnerability_name}: {error_str}")

        # Check if it's a rate limit error (429 or quota exceeded)
        if ('429' in error_str or 'quota' in error_str.lower() or 'rate limit' in error_str.lower()) and retry_count < MAX_RETRIES:
            # Extract retry delay from error message if available
            retry_delay = MIN_CALL_INTERVAL * 2  # Default to 4 seconds

            # Try to extract the retry delay from error message
            match = re.search(r'retry in (\d+(?:\.\d+)?)', error_str, re.IGNORECASE)
            if match:
                retry_delay = float(match.group(1)) + 1  # Add 1 second buffer

            print(f"Rate limit hit. Retrying in {retry_delay} seconds... (Attempt {retry_count + 1}/{MAX_RETRIES})")
            time.sleep(retry_delay)

            # Recursive retry
            return get_mitigation(vulnerability_name, retry_count + 1)

        # Return a generic fallback message for all other errors or max retries exceeded
        if retry_count >= MAX_RETRIES:
            print(f"Max retries exceeded for {vulnerability_name}. Using fallback.")

        return "Update software, apply patches, review configuration, and follow security best practices."

def get_bulk_mitigations(vulnerability_list, max_requests=5):
    """
    Get mitigations for a list of vulnerabilities with rate limiting.

    Args:
        vulnerability_list (list): List of vulnerability names
        max_requests (int): Maximum number of API requests to make (reduced default to 5)

    Returns:
        dict: Dictionary mapping vulnerability names to mitigation advice
    """
    mitigations = {}

    # Limit the number of requests to conserve API credits (reduced from 10 to 5)
    limited_list = vulnerability_list[:max_requests]

    success_count = 0
    for vuln_name in limited_list:
        mitigation = get_mitigation(vuln_name)
        mitigations[vuln_name] = mitigation

        # Check if we got a real mitigation (not fallback)
        if mitigation != "Apply security patches, update software, and follow vendor security guidelines.":
            success_count += 1
            print(f"✓ Got mitigation for: {vuln_name}")
        else:
            print(f"⚠ Using fallback for: {vuln_name}")

        # Stop early if we hit rate limits consistently
        if len(limited_list) > 3 and success_count == 0:
            print("Rate limit hit on all attempts. Stopping API calls and using fallback for remaining items.")
            break

    # For remaining vulnerabilities, use a generic message
    for vuln_name in vulnerability_list[max_requests:]:
        mitigations[vuln_name] = "Apply security patches, update software, and follow vendor security guidelines."

    print(f"\nMitigation Summary: {success_count}/{len(limited_list)} successful API calls")
    return mitigations

def test_api_connection():
    """Test if Gemini API is working correctly."""
    try:
        response = model.generate_content("Test")
        print("Gemini API connection successful!")
        return True
    except Exception as e:
        print(f"Gemini API connection failed: {e}")
        return False

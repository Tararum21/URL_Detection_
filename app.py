import streamlit as st
import requests
from urllib.parse import urlencode

# Bank data mappings
BANKS = {
    "HDFC Bank": "hdfcbank.com",
    "ICICI Bank": "icicibank.com",
    "Axis Bank": "axisbank.com",
    "IndusInd Bank": "indusind.com",
    "State Bank of India (SBI)": "onlinesbi.com",
}

# API keys
WHOXY_API_KEY = "622c4c22df6f04cehc26db76c8c603a47"
URLSCAN_API_KEY = "c7af4acf-276a-41f3-9559-981e6ed53304"

# Utility functions
def fetch_suspicious_domains(api_key, query, official_domain):
    """Fetch domains containing the bank name but differing from its official domain using Whoxy."""
    search_url = f"https://api.whoxy.com/?key={api_key}&whois=true&reverse=whois&search={urlencode({'q': query})}"
    try:
        response = requests.get(search_url)
        if response.status_code == 200:
            results = response.json().get("search_result", [])
            return [entry["domain_name"] for entry in results if official_domain not in entry.get("domain_name", "")]
        else:
            st.error(f"Whoxy API returned status code: {response.status_code}")
    except Exception as e:
        st.error(f"Error connecting to Whoxy API: {e}")
    return []

def perform_urlscan(api_key, target_url):
    """Scan a given URL with URLScan.io."""
    headers = {"API-Key": api_key}
    payload = {"url": target_url, "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload)
        if response.status_code == 200:
            return response.json().get("result")
        else:
            st.error(f"URLScan failed with status: {response.status_code}")
    except Exception as e:
        st.error(f"Error while using URLScan API: {e}")
    return None

def generate_google_dork(bank_name, domain):
    """Create a Google Dork query for finding fraudulent sites."""
    return f"site:{domain} inurl:login -{bank_name.lower()} -{domain}"

# App layout and logic
def scam_detector_app():
    # Page title and description
    st.set_page_config(page_title="Scam URL Detector", page_icon="🔍")
    st.title("Scam URL Detection Tool")
    st.markdown("Secure yourself against phishing and fraudulent websites targeting Indian bank customers.")

    # Sidebar for bank selection
    st.sidebar.header("Choose Your Bank")
    selected_bank = st.sidebar.selectbox("Select a bank", list(BANKS.keys()))
    official_domain = BANKS[selected_bank]

    st.sidebar.markdown("---")
    st.sidebar.write(f"### Official Domain\n[{official_domain}](https://{official_domain})")

    # URL Verification Section
    st.subheader("🔎 Verify a URL")
    user_url = st.text_input("Enter the URL to verify")
    if st.button("Verify URL"):
        if official_domain not in user_url:
            st.error("⚠️ This URL is suspicious! It doesn't match the bank's official domain.")
        else:
            st.success("✅ The URL appears safe.")

    # Suspicious Domain Search
    st.subheader("🌐 Search for Suspicious Domains")
    if st.button("Search Suspicious Domains"):
        search_query = f"{selected_bank} login"
        suspicious_domains = fetch_suspicious_domains(WHOXY_API_KEY, search_query, official_domain)
        if suspicious_domains:
            st.warning("⚠️ Found the following suspicious domains:")
            st.write("\n".join([f"- {domain}" for domain in suspicious_domains]))
        else:
            st.success("No suspicious domains found.")

    # URL Scanning with URLScan.io
    st.subheader("🧾 Analyze URL with URLScan.io")
    scan_url = st.text_input("Enter a URL for deeper analysis")
    if st.button("Run Scan"):
        scan_result = perform_urlscan(URLSCAN_API_KEY, scan_url)
        if scan_result:
            st.success("Scan completed successfully!")
            st.markdown(f"[View Detailed Report]({scan_result})", unsafe_allow_html=True)
        else:
            st.error("URL scanning failed. Please try again later.")

    # Google Dork Query Generation
    st.subheader("🔍 Advanced Search (Google Dork)")
    if st.button("Generate Search Query"):
        dork_query = generate_google_dork(selected_bank, official_domain)
        st.info("Google Dork Query Generated:")
        st.code(dork_query)
        st.markdown(f"[Search on Google](https://www.google.com/search?q={urlencode({'q': dork_query})})", unsafe_allow_html=True)

# Run the app
if __name__ == "__main__":
    scam_detector_app()

import streamlit as st
import pickle
import numpy as np
from urllib.parse import urlparse
import re
import socket

# Feature extraction function
def extract_features(url):
    features = {}

    # Feature: URL Length
    features['URL_Length'] = len(url)
    
    # Feature: Having IP Address
    features['having_IP_Address'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', urlparse(url).netloc) else 0
    
    # Feature: Shortening Service (e.g., bit.ly, tinyurl.com)
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']
    features['Shortining_Service'] = 1 if any(service in url for service in shortening_services) else 0
    
    # Feature: Having "@" Symbol
    features['having_At_Symbol'] = 1 if '@' in url else 0
    
    # Feature: Double Slash Redirecting
    features['double_slash_redirecting'] = 1 if '//' in url[7:] else 0  # Check for '//' after the protocol
    
    # Feature: Prefix-Suffix
    features['Prefix_Suffix'] = 1 if '-' in urlparse(url).netloc else 0
    
    # Feature: Sub-Domains
    features['having_Sub_Domain'] = len(urlparse(url).netloc.split('.')) - 2
    
    # Feature: SSL Final State
    features['SSLfinal_State'] = 1 if url.startswith('https://') else 0

    # Feature: HTTPS Token
    features['HTTPS_token'] = 1 if url.startswith('https://') else 0

    # Feature: Domain Registration Length (Placeholder, you can extract from external APIs)
    features['Domain_registeration_length'] = 0  # Placeholder

    # Feature: Favicon (Placeholder, you can extract from external APIs)
    features['Favicon'] = 0  # Placeholder

    # Feature: Request URL (Placeholder, you can extract using web scraping)
    features['Request_URL'] = 0  # Placeholder

    # Feature: URL of Anchor (Placeholder, you can extract using web scraping)
    features['URL_of_Anchor'] = 0  # Placeholder

    # Feature: Links in Tags (Placeholder, you can extract using web scraping)
    features['Links_in_tags'] = 0  # Placeholder

    # Feature: SFH (Server Form Handler) (Placeholder)
    features['SFH'] = 0  # Placeholder

    # Feature: Submitting to Email (e.g., "mailto:")
    features['Submitting_to_email'] = 1 if 'mailto:' in url else 0
    
    # Feature: Abnormal URL (e.g., length > 75 or other rules you define)
    features['Abnormal_URL'] = 1 if len(url) > 75 else 0  # Example rule
    
    # Feature: Redirect (Multiple slashes)
    features['Redirect'] = 1 if url.count('//') > 1 else 0
    
    # Feature: On Mouseover (Placeholder, can be extracted by inspecting the page content)
    features['on_mouseover'] = 0  # Placeholder
    
    # Feature: RightClick (Placeholder, can be extracted by inspecting the page content)
    features['RightClick'] = 0  # Placeholder
    
    # Feature: PopUpWindow (Placeholder, can be extracted by inspecting the page content)
    features['popUpWidnow'] = 0  # Placeholder
    
    # Feature: Iframe (Placeholder, can be extracted by inspecting the page content)
    features['Iframe'] = 0  # Placeholder
    
    # Feature: Age of Domain (Placeholder, you can use external APIs like whois)
    features['age_of_domain'] = 0  # Placeholder
    
    # Feature: DNS Record (Placeholder, assuming DNS records are valid)
    features['DNSRecord'] = 1  # Placeholder, assuming DNS record exists
    
    # Feature: Web Traffic (Placeholder, you can use external APIs)
    features['web_traffic'] = 0  # Placeholder
    
    # Feature: Page Rank (Placeholder, can be extracted from external sources)
    features['Page_Rank'] = 0  # Placeholder
    
    # Feature: Google Index (True if URL is indexed by Google)
    features['Google_Index'] = 1 if "google.com" in url else 0
    
    # Feature: Links Pointing to Page (Placeholder)
    features['Links_pointing_to_page'] = 0  # Placeholder
    
    # Feature: Statistical Report (Placeholder)
    features['Statistical_report'] = 0  # Placeholder

    # Result placeholder (typically the target variable, not used for feature extraction)
    features['Result'] = 0  # Placeholder for the actual result (e.g., phishing or benign)

    # Feature: Port (Ensure this feature is included as per your model's requirement)
    features['port'] = 0  # You may need to extract the port if necessary (e.g., from urlparse)

    return features

# Load pre-trained model
with open('phishing_random.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

# Streamlit app
def run():
    st.title("Phishing Website Detection")
    
    # Input URL from user
    url = st.text_input("Enter a URL to test (e.g., http://example.com):")
    
    if url:
        # Extract features from the input URL
        features = extract_features(url)
        
        # Align features with model's expected input format
        feature_values = np.array([features[col] for col in model.feature_names_in_]).reshape(1, -1)
        
        # Predict phishing or benign
        prediction = model.predict(feature_values)
        
        # Show the result
        result = "Safe" if prediction[0] == 1 else "Phishing"
        
        st.write(f"The URL is predicted as: {result}")

# Run the Streamlit app
if __name__ == "__main__":
    run()

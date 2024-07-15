import socket
from urllib.parse import urlparse
import base64
import dns.resolver
import pandas as pd
import requests
import streamlit as st
import whois
import altair as alt
import folium
from streamlit_folium import folium_static
from config import VIRUSTOTAL_API_KEY, ALIENVAULT_API_KEY
import tldextract
import re


# Function to get the IP address of the URL
def get_ip_address(url):
    domain = urlparse(url).netloc
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except Exception as e:
        return {"error": str(e)}


# Function to get WHOIS information
def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception as e:
        return {"error": str(e)}


# Function to extract basic information from the URL
def get_url_info(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return {
            "status_code": response.status_code,
            "headers": headers,
            "content": response.content[:500]  # Displaying only first 500 characters
        }
    except Exception as e:
        return {"error": str(e)}


# Function to get geolocation information of an IP address
def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}


# Function to get security information using VirusTotal API
def get_security_info(url):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key is missing"}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


# Function to get historical data from Wayback Machine
def get_historical_data(domain):
    try:
        response = requests.get(f"http://archive.org/wayback/available?url={domain}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}


# Function to get SSL certificate information using SSL Labs API
def get_ssl_info(domain):
    try:
        response = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=on")
        return response.json()
    except Exception as e:
        return {"error": str(e)}


# Function to get DNS records
def get_dns_info(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [str(ip) for ip in result]
    except Exception as e:
        return {"error": str(e)}


# Function to get traffic analysis using SimilarWeb API (placeholder)
def get_traffic_info(domain):
    # This is a placeholder. Replace with actual API call to SimilarWeb or Alexa.
    try:
        return {
            "global_rank": 12345,
            "country_rank": 6789,
            "bounce_rate": "50%",
            "pageviews_per_visitor": 3.2,
            "daily_time_on_site": "2:35"
        }
    except Exception as e:
        return {"error": str(e)}


# Function to get social media mentions using an actual API
def get_social_media_mentions(domain):
    try:
        # Replace with actual API endpoints and authentication as needed
        twitter_response = requests.get(f"https://api.twitter.com/mentions/{domain}")
        twitter_response.raise_for_status()  # Raise error for bad response

        reddit_response = requests.get(f"https://api.reddit.com/mentions/{domain}")
        reddit_response.raise_for_status()

        facebook_response = requests.get(f"https://graph.facebook.com/mentions/{domain}")
        facebook_response.raise_for_status()

        # Example: Extract counts from JSON responses
        twitter_count = twitter_response.json().get('count', 0)
        reddit_count = reddit_response.json().get('count', 0)
        facebook_count = facebook_response.json().get('count', 0)

        return [
            {"platform": "Twitter", "mentions": twitter_count},
            {"platform": "Reddit", "mentions": reddit_count},
            {"platform": "Facebook", "mentions": facebook_count}
        ]
    except requests.exceptions.HTTPError as http_err:
        return {"error": f"HTTP error occurred: {http_err}"}
    except ValueError as val_err:
        return {"error": f"Value error occurred: {val_err}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}


# Function to get SEO analysis (placeholder)
def get_seo_analysis(domain):
    # This is a placeholder. Replace with actual API call to Moz or Ahrefs.
    try:
        return {
            "domain_authority": 50,
            "page_authority": 40,
            "backlinks": 120,
            "spam_score": 1.5
        }
    except Exception as e:
        return {"error": str(e)}


# Function to get threat intelligence from AlienVault
def get_threat_intelligence(domain):
    if not ALIENVAULT_API_KEY:
        return {"error": "AlienVault API key is missing"}
    headers = {
        "X-OTX-API-KEY": ALIENVAULT_API_KEY
    }
    try:
        response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
                                headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


# Function to get sandbox analysis
def get_sandbox_analysis(url):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key is missing"}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}/analysis", headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


# Function to get passive DNS data
def get_passive_dns(domain):
    try:
        response = requests.get(f"https://api.passivedns.com/v1/dns/{domain}")
        response.raise_for_status()  # Check if request was successful
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# Function to analyze subdomains
def analyze_subdomains(domain):
    try:
        subdomains = []
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            subdomains.append(ipval.to_text())
        return subdomains
    except Exception as e:
        return {"error": str(e)}


# Function to analyze the TLD of the URL
def analyze_tld(url):
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    return {
        "tld": tld,
        "common_tld": tld in ["com", "org", "net"],
        "suspicious_tld": tld in ["biz", "info", "xyz"]
    }


# Function to analyze characters in the URL
def analyze_characters(url):
    unusual_patterns = {
        "excessive_special_chars": bool(re.search(r'[^a-zA-Z0-9./:_-]', url)),
        "non_standard_encoding": bool(re.search(r'%[0-9a-fA-F]{2}', url)),
        "unicode_characters": bool(re.search(r'[^\x00-\x7F]', url))
    }
    return unusual_patterns


# Function to calculate risk score
def calculate_risk_score(security_info, whois_info, traffic_info):
    # Simple example of calculating risk score based on placeholders
    score = 0
    if isinstance(security_info, dict) and 'malicious' in security_info:
        score += 50
    if isinstance(whois_info, dict) and 'expiration_date' in whois_info and whois_info['expiration_date'] is None:
        score += 30
    if isinstance(traffic_info, dict) and traffic_info.get('global_rank', 100000) > 100000:
        score += 20
    return score


# Streamlit app
st.title("URL Analytics Master")
st.write("Enter a URL to get detailed information about it. Always enter with http or https.")
st.write("API keys not available for all platforms, might encounter some errors.")
st.write("Owner:- Syed Adnan Ahmed")
st.write("For any Queries or Suggestions:- aadjj41@gmail.com")

url = st.text_input("Enter URL")

if url:
    domain = urlparse(url).netloc

    with st.expander("URL Information"):
        ip_address = get_ip_address(url)
        st.write(f"**IP Address:** {ip_address}")

        whois_info = get_whois_info(domain)
        st.write(f"**WHOIS Information:**")
        try:
            st.json(whois_info)
        except Exception as e:
            st.write(whois_info)

        url_info = get_url_info(url)
        st.write(f"**URL Response Information:**")
        st.json(url_info)

        if isinstance(ip_address, str) and not ip_address.startswith("Error"):
            ip_geolocation = get_geolocation(ip_address)
            st.write(f"**IP Geolocation Information:**")
            if 'lat' in ip_geolocation and 'lon' in ip_geolocation:
                map_center = [ip_geolocation['lat'], ip_geolocation['lon']]
                folium_map = folium.Map(location=map_center, zoom_start=12)
                folium.Marker(map_center, popup=domain, icon=folium.Icon(color='red')).add_to(folium_map)
                folium_static(folium_map)
            else:
                st.write(ip_geolocation)
        else:
            st.write("Cannot retrieve IP geolocation information.")

    with st.expander("Security Information"):
        security_info = get_security_info(url)
        st.json(security_info)

    with st.expander("Historical Data"):
        historical_data = get_historical_data(domain)
        st.json(historical_data)

        if "archived_snapshots" in historical_data and "closest" in historical_data["archived_snapshots"]:
            snapshots = historical_data["archived_snapshots"]["closest"]
            if snapshots:
                df = pd.DataFrame([snapshots])
                chart = alt.Chart(df).mark_line().encode(
                    x='timestamp:T',
                    y='url:N',
                    tooltip=['url', 'timestamp']
                ).interactive()
                st.altair_chart(chart)

    with st.expander("SSL Certificate Information"):
        ssl_info = get_ssl_info(domain)
        st.json(ssl_info)

    with st.expander("DNS Information"):
        dns_info = get_dns_info(domain)
        st.write(f"**DNS Records:** {dns_info}")

    with st.expander("Traffic Analysis"):
        traffic_info = get_traffic_info(domain)
        st.json(traffic_info)

    with st.expander("Social Media Mentions"):
        social_media_mentions = get_social_media_mentions(domain)
        st.json(social_media_mentions)

    with st.expander("SEO Analysis"):
        seo_analysis = get_seo_analysis(domain)
        st.json(seo_analysis)

    with st.expander("Threat Intelligence"):
        threat_info = get_threat_intelligence(domain)
        st.json(threat_info)

    with st.expander("VirusTotal Sandbox Analysis"):
        sandbox_info = get_sandbox_analysis(url)
        st.json(sandbox_info)

    with st.expander("Passive DNS Analysis"):
        passive_dns_info = get_passive_dns(domain)
        st.json(passive_dns_info)

    with st.expander("Subdomain Analysis"):
        subdomains = analyze_subdomains(domain)
        st.write(f"**Subdomains:** {subdomains}")

    with st.expander("TLD Analysis"):
        tld_info = analyze_tld(url)
        st.json(tld_info)

    with st.expander("Character Analysis"):
        char_analysis = analyze_characters(url)
        st.json(char_analysis)

    with st.expander("URL Risk Score"):
        risk_score = calculate_risk_score(security_info, whois_info, traffic_info)
        st.write(f"**Risk Score:** {risk_score}")

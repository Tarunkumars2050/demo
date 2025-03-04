import streamlit as st
from url_safety_check import check_url_safety
import tldextract

st.title("URL Safety Checker")
st.write("This app checks the safety of a given URL using various criteria including SSL, domain reputation, and Google Safe Browsing API.")

url = st.text_input("Enter a URL to check:")

if st.button("Check URL Safety"):
    if url:
        is_safe, message = check_url_safety(url)
        if is_safe:
            st.success(f"The URL is safe: {message}")
        else:
            st.error(f"The URL is unsafe: {message}")
    else:
        st.warning("Please enter a URL to check.")

st.info("Note: This tool provides a general assessment and should not be the sole factor in determining a URL's safety.")

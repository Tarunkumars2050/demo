import streamlit as st
from url_safety_check import check_url_safety
from url_safety_check import check_url_safety

st.write("Enter a URL to determine whether it is safe or not.")

url = st.text_input("Enter URL:")

if st.button("Check Safety"):
    is_safe, message = check_url_safety(url)
    if is_safe:
        st.success(f"The URL is safe: {message}")
    else:
        st.error(f"The URL is unsafe: {message}")

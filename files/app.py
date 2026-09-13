import streamlit as st
import hashlib
import requests

st.set_page_config(
    page_title="ZyberGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ ZyberGuard")
st.subheader("Cybersecurity Monitoring & File Integrity Tool")

st.write(
    "ZyberGuard is a cybersecurity application that provides "
    "file integrity checking, SHA-256 hashing and IP information lookup."
)

tab1, tab2 = st.tabs(["🔐 File Integrity", "🌐 IP Lookup"])

# ---------------- FILE INTEGRITY ----------------
with tab1:
    st.header("File Integrity Checker")

    uploaded_file = st.file_uploader(
        "Upload a file to calculate its SHA-256 hash",
        type=None
    )

    if uploaded_file:
        file_data = uploaded_file.read()

        sha256_hash = hashlib.sha256(file_data).hexdigest()

        st.success("File analyzed successfully!")

        st.write("**File Name:**", uploaded_file.name)
        st.write("**File Size:**", f"{len(file_data)} bytes")

        st.code(sha256_hash, language="text")

        st.info(
            "SHA-256 can be used as a digital fingerprint to "
            "verify whether a file has been changed."
        )

# ---------------- IP LOOKUP ----------------
with tab2:
    st.header("IP Information Lookup")

    ip = st.text_input(
        "Enter an IP address",
        placeholder="8.8.8.8"
    )

    if st.button("Lookup IP"):
        if ip:
            try:
                response = requests.get(
                    f"http://ip-api.com/json/{ip}",
                    timeout=5
                )

                data = response.json()

                if data.get("status") == "success":
                    st.success("IP information retrieved!")

                    col1, col2 = st.columns(2)

                    with col1:
                        st.write("**IP:**", data.get("query"))
                        st.write("**Country:**", data.get("country"))
                        st.write("**City:**", data.get("city"))

                    with col2:
                        st.write("**ISP:**", data.get("isp"))
                        st.write("**Organization:**", data.get("org"))
                        st.write("**Timezone:**", data.get("timezone"))

                else:
                    st.error("Could not find information for this IP.")

            except Exception as e:
                st.error("Unable to connect to the IP lookup service.")
        else:
            st.warning("Please enter an IP address.")

st.divider()

st.caption("ZyberGuard | Cybersecurity Hackathon Project")
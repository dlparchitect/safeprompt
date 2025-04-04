# # SafePrompt.py - Symantec Data Loss Prevention Detection REST API 2.0 Example
# 
# This Streamlit application provides a front-end interface for safely interacting with popular LLMs while enforcing Symantec Data Loss Prevention (DLP) policies through a Symantec DLP detection API.
# https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection.html
# 
# > **Provided as-is**. This script assumes you have access to a functioning DLP Detection Server or API Appliance configured to receive requests as described below.
# 
# ---
# 
# ## Installation
# 
# Install the required libraries:
# 
# ```bash
# pip install streamlit base64 json requests os mimetypes urllib3 openai anthropic google-generativeai
# ```
# 
# ---
# 
# ## Usage
# 
# Start the Streamlit app:
# 
# ```bash
# streamlit run your_script.py
# ```
# 
# Then, use the web interface to:
# - Enter your prompt
# - Choose your preferred LLM vendor: OpenAI, Anthropic, or Google
# - Enable or disable DLP validation for both input and output
# - Optionally upload a file to scan alongside the prompt
# 
# ---
# 
# ## Configuration
# 
# Update your API keys in the script:
# 
# ```python
# openai_api_key = "YOURKEY"
# anthropic_api_key = "YOURKEY"
# google_api_key = "YOURKEY"
# ```
# 
# Update your DLP API URL:
# 
# ```python
# dlp_url = "https://DLP-Detect-Host:DLP-Detect-Port/v2.0/DetectionRequests"
# ```
# 
# ### Authentication Placeholder
# 
# > You may need to include authentication headers or tokens depending on your Symantec DLP detection server configuration and corporate policies.  
# > https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection/about-the-api-detection-server2/creating-keystores-and-truststores-for-the-api-detection-server.html
# 
# ---
# 
# ## DLP Context
# 
# The `dlp_context` object contains metadata passed to the DLP engine. This context is **highly customizable** and can influence detection logic (e.g., filters, user metadata, risk scores).
# 
# > _https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection/overview-of-the-detection-rest-api-2-0/detection-requests-for-the-dlp-detection-rest-api-2-0/detection-request-format-and-definitions/context-entries.html
# 
# Example context fields:
# 
# ```python
# dlp_context = [
#     {"name": "common.dataType", "value": ["DIM"]},
#     {"name": "common.filter", "value": ["d0eb53c4-6d08-47f1-b289-3da151b40426"]},
#     {"name": "common.user.name", "value": ["My Favorite User"]},
#     ...
# ]
# ```
# 
# ---
# 
# ## Section: `common.filter` – Purpose and Setup
# 
# `common.filter` is a **critical field** used to direct DLP detection requests through a specific **policy filter** on your DLP server.
# https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection/managing-application-detection.html
# 
# Install the required libraries
# streamlit base64 json requests os mimetypes urllib3


import streamlit as st
import base64
import json
import requests
import os
import mimetypes
import urllib3
from openai import OpenAI
import anthropic
import google.generativeai as genai

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== API Configuration ==========
openai_api_key = "YOURKEY"
anthropic_api_key = "YOURKEY"
google_api_key = "YOURKEY"

# ========== Models as of 04/02/2025 ==========
openai_model = "gpt-4o-mini"
anthropic_model = "claude-3-7-sonnet-20250219"
google_model = "gemini-1.5-pro-002"


# ========== Models as of 04/02/2025 ==========
openai_model = "gpt-4o-mini"
anthropic_model = "claude-3-7-sonnet-20250219"
google_model = "gemini-1.5-pro-002"

dlp_url = "https://DLP-Detect-Host:DLP-Detect-Port/v2.0/DetectionRequests"
headers = {"Content-Type": "application/json"}

dlp_context = [
    {"name": "common.dataType", "value": ["DIM"]},
    {"name": "common.filter", "value": ["d0eb53c4-6d08-47f1-b289-3da151b40426"]},
    {"name": "common.application", "value": ["GenAI Front End"]},
    {"name": "network.direction", "value": ["upload"]},
    {"name": "email.envelope.sender", "value": ["a@myco.com"]},
    {"name": "email.envelope.recipient", "value": ["joe@example.com", "bob@example.com"]},
    {"name": "email.header.sender", "value": ["slava@myco.com"]},
    {"name": "email.header.recipient", "value": ["joe@example.com", "bob@example.com"]},
    {"name": "common.transactionId", "value": ["12345"]},
    {"name": "location.region", "value": ["Mountain View, CA United States"]},
    {"name": "location.region.country", "value": ["DZ"]},
    {"name": "http.url", "value": ["http://google.com/ancident"]},
    {"name": "link.uba", "value": ["http://google.com/uba"]},
    {"name": "link.doc.exposure", "value": ["http://google.com/docexposures"]},
    {"name": "link.service.file.activity", "value": ["http://google.com/servicefileactivity"]},
    {"name": "link.incident", "value": ["http://google.com/incident"]},
    {"name": "link.service.application", "value": ["http://google.com/serviceapplication"]},
    {"name": "common.user.name", "value": ["My Favorite User"]},
    {"name": "common.doc.isInternal", "value": ["True"]},
    {"name": "common.doc.id", "value": ["0123456789" * 12]},
    {"name": "common.doc.exposures.public", "value": ["True"]},
    {"name": "common.user.threatScore", "value": ["99"]},
    {"name": "common.doc.type", "value": ["folder"]},
    {"name": "common.folder", "value": ["/z/c/a"]},
    {"name": "common.user.id", "value": ["zzz"]},
    {"name": "common.doc.activityCount", "value": ["3"]},
    {"name": "common.doc.creatorId", "value": ["321"]},
    {"name": "common.doc.parentFolderId", "value": ["123"]},
    {"name": "http.method", "value": ["GET"]},
    {"name": "http.cookies", "value": ["G123213ET"]},
    {"name": "device.type", "value": ["mobile"]},
    {"name": "http.siteRiskScore", "value": ["70"]},
    {"name": "http.browser", "value": ["chrome"]},
    {"name": "common.user.activityType", "value": ["upload"]}
]

def handle_openai(prompt):
    client = OpenAI(api_key=openai_api_key)
    response = client.responses.create(model=openai_model, input=prompt)
    return response.output[0].content[0].text

def handle_anthropic(prompt):
    client = anthropic.Anthropic(api_key=anthropic_api_key)
    response = client.messages.create(
        model=anthropic_model,
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text

def handle_google(prompt):
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel(google_model)
    response = model.generate_content(prompt)
    return response.text

def encode_file(file):
    file_bytes = file.read()
    encoded = base64.b64encode(file_bytes).decode("utf-8")
    mime_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
    return {
        "contentBlockId": "block_file",
        "mimeType": mime_type,
        "fileName": file.name,
        "data": encoded
    }

def send_dlp(data, label, uploaded_file=None):
    encoded_data = base64.b64encode(data.encode("utf-8")).decode("utf-8")
    attachments = [encode_file(uploaded_file)] if uploaded_file else []

    payload = {
        "context": dlp_context,
        "body": {"contentBlockId": "block1", "mimeType": "text/plain", "data": encoded_data if label == "body" else ""},
        "subject": {"contentBlockId": "subjectBlock1", "mimeType": "text/plain", "data": encoded_data if label == "subject" else ""},
        "attachments": attachments
    }

    try:
        response = requests.post(dlp_url, headers=headers, data=json.dumps(payload), verify=False)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def check_dlp(data, label, uploaded_file=None):
    result = send_dlp(data, label, uploaded_file)

    custom_message = None
    is_blocked = False

    for action in result.get("responseAction", []):
        for param in action.get("parameter", []):
            if param.get("name") == "customResponsePayload":
                message = param.get("value", [""])[0]
                custom_message = message
                if "blocked" in message.lower():
                    is_blocked = True

    parsed_violations = []
    for v in result.get("violation", []):
        parsed_violations.append(f"**Policy Violation**: `{v['name']}`**Policy ID**: `{v['policyId']}`")

    if "error" in result:
        return False, [f"Error: {result['error']}"], custom_message, is_blocked

    return True, parsed_violations, custom_message, is_blocked

st.set_page_config(page_title="SafePrompt - Symantec DLP API", page_icon="logo-DLP.ico", layout="wide")
st.title("🔐 SafePrompt - Symantec DLP API")

prompt = st.text_area("Enter your prompt:")
vendor = st.selectbox("Choose AI Vendor", ["OpenAI", "Anthropic", "Google"])
dlp_prompt_check = st.checkbox("Enable Symantec DLP validation for prompt", value=True)
dlp_response_check = st.checkbox("Enable Symantec DLP validation for AI response", value=True)
uploaded_file = st.file_uploader("Upload file (optional):", type=None)

if st.button("Run"):
    if not prompt:
        st.warning("Please enter a prompt.")
    else:
        with st.spinner("Processing..."):

            if uploaded_file:
                st.info("📄 The uploaded file's contents will be included in the prompt.")
                try:
                    file_content = uploaded_file.read().decode("utf-8", errors="ignore")
                    prompt += f"\n\n[File Content Starts Below]\n{file_content}"
                    uploaded_file.seek(0)
                except Exception as e:
                    st.warning(f"⚠️ Failed to include file content in prompt: {e}")

            if dlp_prompt_check:
                valid, violations, custom_message, blocked = check_dlp(prompt, "body", uploaded_file)

                if custom_message:
                    st.markdown(f"📢 **DLP Response Message**:> {custom_message}")

                if violations:
                    st.markdown("### 🚨 Sensitive Information  in Prompt")
                    for v in violations:
                        st.markdown(f"- {v}")

                if blocked:
                    st.error("🚫 Prompt blocked by Symantec DLP.")
                    st.stop()

            try:
                if vendor == "OpenAI":
                    response = handle_openai(prompt)
                elif vendor == "Anthropic":
                    response = handle_anthropic(prompt)
                elif vendor == "Google":
                    response = handle_google(prompt)
                else:
                    st.error("Invalid vendor selected.")
                    st.stop()
            except Exception as e:
                st.error(f"❌ LLM Error: {e}")
                st.stop()

            if dlp_response_check:
                valid, violations, custom_message, blocked = check_dlp(response, "subject")

                if custom_message:
                    st.markdown(f"📢 **DLP Response Message**:> {custom_message}")

                if violations:
                    st.markdown("### 🚨 Sensitive Information in AI Response")
                    for v in violations:
                        st.markdown(f"- {v}")

                if blocked:
                    st.error("🚫 Response blocked by Symantec DLP.")
                    st.stop()

            st.success("✅ AI Response")
            st.code(response, language="text")

# SafePrompt.py - Symantec Data Loss Prevention Detection REST API 2.0 Example

This Streamlit application provides a front-end interface for safely interacting with popular LLMs while enforcing Symantec Data Loss Prevention (DLP) policies through a Symantec DLP detection API.
https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection.html

> **Provided as-is**. This script assumes you have access to a functioning DLP Detection Server or API Appliance configured to receive requests as described below.

---

## Installation

Install the required libraries:

```bash
pip install streamlit base64 json requests os mimetypes urllib3 openai anthropic google-generativeai
```

---

## Usage

Start the Streamlit app:

```bash
streamlit run your_script.py
```

Then, use the web interface to:
- Enter your prompt
- Choose your preferred LLM vendor: OpenAI, Anthropic, or Google
- Enable or disable DLP validation for both input and output
- Optionally upload a file to scan alongside the prompt

---

## Configuration

Update your API keys in the script. PLEASE MAKE SURE YOU  PROTECT YOUR KEYS.

```python
openai_api_key = "YOURKEY"
anthropic_api_key = "YOURKEY"
google_api_key = "YOURKEY"
```

Update your DLP API URL:

```python
dlp_url = "https://DLP-Detect-Host:DLP-Detect-Port/v2.0/DetectionRequests"
```

### Authentication Placeholder

> You may need to include authentication headers or tokens depending on your Symantec DLP detection server configuration and corporate policies.  
> https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection/about-the-api-detection-server2/creating-keystores-and-truststores-for-the-api-detection-server.html

---

## DLP Context

The `dlp_context` object contains metadata passed to the DLP engine. This context is **highly customizable** and can influence detection logic (e.g., filters, user metadata, risk scores).

> _https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection/overview-of-the-detection-rest-api-2-0/detection-requests-for-the-dlp-detection-rest-api-2-0/detection-request-format-and-definitions/context-entries.html

Example context fields:

```python
dlp_context = [
    {"name": "common.dataType", "value": ["DIM"]},
    {"name": "common.filter", "value": ["d0eb53c4-6d08-47f1-b289-3da151b40426"]},
    {"name": "common.user.name", "value": ["My Favorite User"]},
    ...
]
```

---

## Section: `common.filter` – Purpose and Setup

`common.filter` is a **critical field** used to direct DLP detection requests through a specific **policy filter** on your DLP server.
https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-application-detection/managing-application-detection.html

### 🛠️ How to Create a Filter

1. Log into your Symantec DLP console.
2. Configure Application Detection for API Detection Servers
3. Navigate to the Manage > Application Detection > Configuration page.
4. Click New Configuration.
5. The New Configuration page appears.
6. In the Name field, enter a name for your application detection configuration.
7. In the Type drop-down list, select API Detection.
8. In the Policy Groups field, select the policy group or groups you want to apply to this configuration.
9. Click Save.
10.  Open the configuration you just created and copy the ID 
11. Replace the `value` in `"common.filter"` with your filter's UUID.

Example:
```python
{"name": "common.filter", "value": ["your-filter-uuid-here"]}
```

---

## File Upload Support

Files uploaded through the UI will be Base64 encoded and submitted with the DLP scan. This enables detection on both the prompt and the file content.

---

##  Notes

- SSL verification is disabled by default (`verify=False`). Change this in production environments.
- Custom messages from the DLP server will be shown in the UI if returned.
- Violations and policy IDs are printed with basic formatting.

---

## Version Info

- DLP fields and API model names are current as of **April 2, 2025**.
- Models used:
  - OpenAI: `gpt-4o-mini`
  - Anthropic: `claude-3-7-sonnet-20250219`
  - Google: `gemini-1.5-pro-002`

---

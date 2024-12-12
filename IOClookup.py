import pandas as pd
import re
import requests

# Function to validate IOC type
def get_ioc_type(ioc):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$", ioc):
        return "IP address"
    elif re.match(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$", ioc):
        return "File hash"
    elif re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", ioc):
        return "Domain"
    elif re.match(r"^https?://", ioc):
        return "URL"
    else:
        return "unknown"

# Function to get verdict based on VirusTotal API response
def get_verdict(ioc_type, ioc_value, api_key):
    base_url = "https://www.virustotal.com/api/v3/"
    headers = {"x-apikey": api_key}
    vt_link_base = "https://www.virustotal.com/gui/"
    url = ""
    vt_link = None

    if ioc_type == "IP address":
        url = f"{base_url}ip_addresses/{ioc_value}"
        vt_link = f"{vt_link_base}ip-address/{ioc_value}"
    elif ioc_type == "File hash":
        url = f"{base_url}files/{ioc_value}"
        vt_link = f"{vt_link_base}file/{ioc_value}"
    elif ioc_type == "Domain":
        url = f"{base_url}domains/{ioc_value}"
        vt_link = f"{vt_link_base}domain/{ioc_value}"
    elif ioc_type == "URL":
        vt_id = re.sub(r"[^a-zA-Z0-9]", "-", ioc_value.strip("/").lower())
        url = f"{base_url}urls/{vt_id}"
        vt_link = f"{vt_link_base}url/{vt_id}"
    else:
        return "Unknown", None

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        if "data" in data:
            malicious = data["data"].get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious == 0:
                return "Clean", vt_link
            elif malicious < 10:
                return "Suspicious", vt_link
            else:
                return "Malicious", vt_link
        else:
            return "Not Found", vt_link
    else:
        return "Error", vt_link

# Main script
def main():
    # Get input from user
    input_file = input("Enter the path to the Excel file: ")
    api_key = input("Enter your VirusTotal API key: ")

    try:
        # Load the Excel file
        data = pd.read_excel(input_file, dtype=str, keep_default_na=False)  # Ensure values are read as strings and empty cells remain empty strings

        # Ensure the column "IOC value" exists
        if "IOC value" not in data.columns:
            print("The input file must contain a column named 'IOC value'.")
            return

        # Prepare results DataFrame
        results = pd.DataFrame(columns=["IOC Type", "IOC Value", "Verdict", "VirusTotal Link"])

        for ioc_value in data["IOC value"]:
            ioc_value = ioc_value.strip()  # Ensure the value is trimmed
            ioc_type = get_ioc_type(ioc_value)
            verdict, vt_link = get_verdict(ioc_type, ioc_value, api_key)
            results = pd.concat([results, pd.DataFrame([{
                "IOC Type": ioc_type,
                "IOC Value": ioc_value,  # Preserve original value
                "Verdict": verdict,
                "VirusTotal Link": vt_link
            }])], ignore_index=True)

        # Save results to Excel
        results.to_excel("results.xlsx", index=False, engine="openpyxl")  # Explicitly set engine to avoid compatibility issues
        print("Results saved to 'results.xlsx'.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

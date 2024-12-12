# IOClookup
# VirusTotal IOC Query Automation Script

This script automates the process of querying the VirusTotal API using a list of Indicators of Compromise (IOCs) from an Excel file. It identifies the type of each IOC, queries VirusTotal for its analysis, and outputs the results in a new Excel file.

---

## Features

- Validates the type of IOC (IP Address, File Hash, Domain, or URL) using regular expressions.
- Queries the VirusTotal API for analysis data.
- Classifies the IOC based on the number of malicious flags:
    - **Clean**: No malicious flags.
    - **Suspect**: Fewer than 10 malicious flags.
    - **Malicious**: 10 or more malicious flags.
    - **Not Found**: IOC not found in VirusTotal.
- Generates a results file (`results.xlsx`) with the following columns:
    - **IOC Type**: The type of IOC (IP Address, File Hash, Domain, URL).
    - **IOC Value**: The original IOC value from the input file.
    - **Verdict**: Classification based on the VirusTotal analysis.
    - **VirusTotal Link**: The link to the IOC's analysis on VirusTotal (ensure that no characters are present that make the link unclickable or mask the IOC Value).

---

## Requirements

- Python 3.7 or higher
- Libraries:
    - `pandas`
    - `openpyxl`
    - `requests`

Install required libraries with:

```bash
pip install pandas openpyxl requests
```

---

## Usage

1. Save the script to a file, e.g., `IOClookup.py`.
2. Prepare an Excel file with a single column named `IOC value`, containing the IOCs to analyze.
3. Run the script:
    
    ```bash
    python IOClookup.py
    ```
    
4. When prompted, provide:
    - The path to the Excel file.
    - Your VirusTotal API key.
5. The script will generate a new Excel file named `results.xlsx` in the current directory.
6. Ensure to defang your IOC Values (remove any characters that make links unclickable or mask the IOC Value).
- The script uses VirusTotal's API v3.

---

## Output

The `results.xlsx` file will include:

- **IOC Type**: Identified type of IOC (e.g., "IP Address").
- **IOC Value**: Original IOC from the input.
- **Verdict**: Analysis result ("Clean", "Suspect", "Malicious", or "Not Found").
- **VirusTotal Link**: Direct link to the IOC's analysis on VirusTotal.

---

## Notes

- Ensure your VirusTotal API key has sufficient request quota.
- The input file must have a column named `IOC value`. Otherwise, the script will not run.
- Always ensure your IOC values are defanged properly to allow the script to run correctly.

---

## License

This script is provided "as-is" for educational and operational purposes. No warranties or guarantees are provided.


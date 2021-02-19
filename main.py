import pandas as pd
import os
import itertools 
from collections import defaultdict

"""
Description: This script performs automatic filtering/aggregation of Qualys scans intended for analysis. Reads in a csv file and outputs a csv file. 
"""
def main(): 
    root = os.path.dirname(os.path.abspath(__file__))
    in_file = "supp.csv"
    out_file = "testsupp_results_v2.csv"

    # Get first and last valid lines for entries in the CSV (automatically detect header/footer and skip)
    def get_line_number(phrase, file_path):
        with open(file_path, encoding="utf8") as f:
            for i, line in enumerate(f, 1):
                if phrase in line:
                    return i

    top_line_number = get_line_number("host scanned", root + os.path.sep + in_file)
    bottom_line_number = get_line_number("hosts not scanned", root + os.path.sep + in_file)
    total_line_number = 0

    # Get total # of lines to calculate how many to skip
    with open(root + os.path.sep + in_file, encoding="utf8") as f:
        total_line_number = sum(1 for _ in f)

    skip_top_lines = top_line_number - 2  # 1 for header, 1 for blank line
    skip_bottom_lines = total_line_number - bottom_line_number + 1

    # DEBUG
    # print(top_line_number, bottom_line_number, total_line_number)
    # print(skip_top_lines, skip_bottom_lines)

    """
    read_cols = ["IP", "DNS", "NetBIOS", "OS", "IP Status", "QID", "Title", "Type", "Severity", "Port", "Protocol", "FQDN", "SSL", "CVE ID", "Vendor Reference", "Bugtraq ID", "CVSS Base", \
    "CVSS Temporal", "CVSS3 Base", "CVSS3 Temporal", "Threat", "Impact", "Solution", "Exploitability", "Associated Malware", "Results", "PCI Vuln", "Instance", "Category"]
    """

    read_cols = ["IP", "QID", "Title", "Type", "Severity", "Port", "CVE ID", "Threat"] 
    req_cols = [i for i in read_cols if i not in ["IP", "Port", "CVE ID"]]
    df = pd.read_csv(root + os.path.sep + in_file, index_col=False, skiprows=skip_top_lines, skipfooter=skip_bottom_lines, usecols=read_cols)

    # DEBUG
    # print(df.head())
    # print(df.tail())

    IP_DICT = defaultdict(set)
    PORT_DICT = defaultdict(set)
    CVE_DICT = defaultdict(set)
    COUNT_DICT = defaultdict(int)

    def add_to_dict(key, value, dict):
        # if not pd.isna(value):  # exclude NaNs (empty cells)
        dict[key].add(value)

    def generate_df_from_dict(dict, col_name): 
        # note: this disallows display of lists of considerable length
        data = [[key, str(list(val))[1:-1]] for key, val in dict.items() if len(val) < 1337]  
        return pd.DataFrame(data, columns=["QID", col_name])

    # Iterating over two columns, use `zip`
    for x, y in zip(df["QID"], df["IP"]):
        if not pd.isna(y):  # exclude NaNs (empty cells)
            add_to_dict(x, str(y), IP_DICT)

    for x, y in zip(df["QID"], df["Port"]):
        if not pd.isna(y):  # exclude NaNs (empty cells)
            add_to_dict(x, str(int(y)), PORT_DICT)
        
    for x, y in zip(df["QID"], df["CVE ID"]):
        if not pd.isna(y):  # exclude NaNs (empty cells)
            add_to_dict(x, str(y), CVE_DICT)

    ip_df = generate_df_from_dict(IP_DICT, "IPs")
    port_df = generate_df_from_dict(PORT_DICT, "Ports")
    cve_df = generate_df_from_dict(CVE_DICT, "CVE ID")

    # Create the IP count df
    for k, v in IP_DICT.items(): 
        COUNT_DICT[k] = len(v)
    data = [[key, val] for key, val in COUNT_DICT.items()]
    count_df = pd.DataFrame(data, columns=["QID", "Count"])

    # DEBUG
    # print(ip_df.head())
    # print(port_df.head())
    # print(cve_df.head())
    # print(count_df.head())
    
    df = df.groupby(req_cols).count().reset_index()
    df.drop(columns=["IP", "Port", "CVE ID"], inplace=True) # at this point, only necessary cols in df

    df = df.merge(ip_df, how="left", on="QID")
    df = df.merge(port_df, how="left", on="QID")
    df = df.merge(cve_df, how="left", on="QID")
    df = df.merge(count_df, how="left", on="QID")

    df = df.reindex(columns = ["QID", "Title", "Type", "Severity", "Threat", "Notes", "Metasploit Modules", "CVE ID", "Count", "Ports", "IPs"], fill_value="NA")

    # DEBUG
    # print(df.head())
    # print(df.tail())
    # print(df.dtypes)

    df.to_csv(root + os.path.sep + out_file)


if __name__ == "__main__": 
    main()
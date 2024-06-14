import sys
import re
import os
import csv

# Print welcome message
print('')
print('##### MALSTRINGS by Michael Leclair #####')
print(
    "[*] Mal_Strings is a Python script designed to automate the process of searching for potential indicators of compromise in a given file.")
print(
    "[*] The script uses a combination of regular expressions and custom indicators to identify URLs, domain names, IP addresses, file names, and file paths that may indicate the presence of malicious activity.")
print(
    '[*] Mal_Strings comes with a pre-populated "indicators.txt" file, which contains a list of commonly used terms associated with cyber threats. You can add your own custom indicators to this file to make the search more specific to your needs.')
print('')

# Print usage message
print("[!] Usage: python mal_strings_vX.X.py <indicators.txt> <file_to_search>\n")

# Prompt user to press any key to continue
input("Press any ENTER to continue...")

# Clear user input
#input("\033c")

# The script will continue running and won't proceed until the user presses enter

# Check if the required number of arguments are provided
if len(sys.argv) != 3:
    print("Usage: python string_search.py <indicators.txt> <file_to_search>")
    sys.exit(1)

# Get the file names from the arguments
indicators_file = sys.argv[1]
file_to_search = sys.argv[2]

# Check if the input files exist
if not os.path.exists(indicators_file):
    print(f"{indicators_file} not found")
    sys.exit(1)
if not os.path.exists(file_to_search):
    print(f"{file_to_search} not found")
    sys.exit(1)

def regex_searches():
    # Open the input files and read their contents
    with open(file_to_search, "r") as f:
        file_content = f.readlines()

    # Create regex patterns to search for the indicators
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ipv6_pattern = r"\b(?:[a-fA-F\d]{1,4}:){7}[a-fA-F\d]{1,4}\b"
    url_pattern = r"(?i)\b(?:https?://)?(?:www\.)?[a-z0-9]+(?:[-._][a-z0-9]+)*\.[a-z]{2,6}\b(?:/[a-z0-9]+)*"
    domain_pattern = r"(?i)\b(?:[a-z0-9]+(?:[-._][a-z0-9]+)*\.)+[a-z]{2,6}\b"
    filename_pattern = r"(?i)\b[a-z0-9]+(?:[-._][a-z0-9]+)*\.[a-z]{2,6}\b"
    filepath_pattern = r"(?i)\b(?:/[\w.-]+)+/\b[a-z0-9]+(?:[-._][a-z0-9]+)*\.[a-z]{2,6}\b"

    # Search for the indicators in the file
    ipv4_matches = [(line_num, line) for line_num, line in enumerate(file_content) if re.search(ipv4_pattern, line)]
    ipv6_matches = [(line_num, line) for line_num, line in enumerate(file_content) if re.search(ipv6_pattern, line)]
    url_matches = [(line_num, line) for line_num, line in enumerate(file_content) if re.search(url_pattern, line)]
    domain_matches = [(line_num, line) for line_num, line in enumerate(file_content) if re.search(domain_pattern, line)]
    filename_matches = [(line_num, line) for line_num, line in enumerate(file_content) if re.search(filename_pattern, line)]
    filepath_matches = [(line_num, line) for line_num, line in enumerate(file_content) if re.search(filepath_pattern, line)]

    # Create the output directory if it doesn't exist
    output_dir = "Results_Strings_Searches"
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    # Write the search results to a CSV file with two columns for each category, where each result includes the entire line
    output_file = f"{output_dir}/RegEx_Strings_Search.csv"
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Search Term", "Line Number", "Line"])
        # Write the IPv4 matches to the CSV file
        for line_num, line in ipv4_matches:
            writer.writerow(["IPv4 Address", line_num + 1, line.strip()])

        # Write the IPv6 matches to the CSV file
        for line_num, line in ipv6_matches:
            writer.writerow(["IPv6 Address", line_num + 1, line.strip()])

        # Write the URL matches to the CSV file
        for line_num, line in url_matches:
            writer.writerow(["URL", line_num + 1, line.strip()])

        # Write the domain matches to the CSV file
        for line_num, line in domain_matches:
            writer.writerow(["Domain Name", line_num + 1, line.strip()])

        # Write the filename matches to the CSV file
        for line_num, line in filename_matches:
            writer.writerow(["File Name with Extension", line_num + 1, line.strip()])

        # Write the filepath matches to the CSV file
        for line_num, line in filepath_matches:
            writer.writerow(["File Path with Name and Extension", line_num + 1, line.strip()])

    print(f"[*] RegEx Search results written to {output_file}")

def ioc_searches():
    # create directory for output file
    output_dir = "Results_Strings_Searches"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # open indicators file and read search terms into a list
    with open(indicators_file, "r") as f:
        search_terms = [line.strip() for line in f.readlines()]

    # search the file for each search term
    results = []
    with open(file_to_search, "r") as f:
        for i, line in enumerate(f.readlines()):
            for search_term in search_terms:
                if search_term.lower() in line.lower():
                    results.append((search_term, i+1, line.strip()))

    # write results to CSV file
    output_file = os.path.join(output_dir, "IOC_Strings_Search.csv")
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Search Term", "Line Number", "Line"])
        for result in results:
            writer.writerow(result)

    print(f"[*] IOC Search results written to {output_file}")


if __name__ == "__main__":
    regex_searches()
    ioc_searches()
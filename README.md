# mal_strings

Mal_Strings is a Python script designed to automate the process of searching for potential indicators of compromise in a given file, especially for binary strings dumps.

The script uses a combination of regular expressions and custom indicators to identify URLs, domain names, IP addresses, file names, and file paths that may indicate the presence of malicious activity.

Mal_Strings comes with a pre-populated "indicators.txt" file, which contains a list of commonly used terms associated with cyber threats. You can add your own custom indicators to this file to make the search more specific to your needs.

Usage: python mal_strings_vX.X.py <indicators.txt> <file_to_search>

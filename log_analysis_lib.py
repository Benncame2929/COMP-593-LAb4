"""
Library of functions that are useful for analyzing plain-text log files.
"""
import sys
import os
import re

def obtain_log_file_path(param_num=1):
   
    if len(sys.argv) <= param_num:
        print(f"Error: Missing log file path at command line parameter {param_num}.")
        sys.exit("Terminating script.")
    log_path = os.path.abspath(sys.argv[param_num])
    if not os.path.isfile(log_path):
        print(f"Error: The path '{log_path}' does not refer to a valid file.")
        sys.exit("Terminating script.")
    return log_path

def extract_log_with_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False):
   
    filtered_records = []
    captured_data = []
    flags = re.IGNORECASE if ignore_case else 0
    with open(log_path, 'r') as file:
        for record in file:
            match = re.search(regex, record, flags)
            if match:
                filtered_records.append(record.strip())
                if match.lastindex:
                    captured_data.append(match.groups())
    if print_records:
        print(*filtered_records, sep='\n')
    if print_summary:
        print(f"The log file contains {len(filtered_records)} records matching the regex '{regex}' (case-{'in' if ignore_case else ''}sensitive).")
    return (filtered_records, captured_data)

if __name__ == '__main__':
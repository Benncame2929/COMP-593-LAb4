"""
Library of functions that are useful for analyzing plain-text log files.
"""
import sys
import os
import re
import pandas as pd
import log_analysis_lib


def main():
    # Get the log file path from the command line
    log_path = get_file_path_from_cmd_line()

    
    return

def get_file_path_from_cmd_line(param_num=1):
    
    if len(sys.argv) <= param_num:
        print(f'Error: Missing log file path at command line parameter {param_num}.')
        sys.exit('Terminating script.')
    
    log_path = os.path.abspath(sys.argv[param_num])
    if not os.path.isfile(log_path):
        print(f'Error: The path "{log_path}" does not refer to a valid file.')
        sys.exit('Terminating script.')



    
    return

def filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary is True:
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')

    return (filtered_records, captured_data)

if __name__ == '__main__':
    main()        
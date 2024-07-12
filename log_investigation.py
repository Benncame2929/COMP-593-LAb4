import re
import pandas as pd
import log_analysis_lib

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    log_file = obtain_log_file_path(1)
    port_traffic = analyze_port_traffic(log_file)
    for port, count in port_traffic.items():
        if count >= 100:
            create_port_traffic_report(log_file, port)
    report_invalid_user_logins(log_file)
    log_records_from_source_ip(log_file, '220.195.35.40')


def analyze_port_traffic(log_file):
    port_counts = {}
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'DPT=(\d+)', line)
            if match:
                port = match.group(1)
                if port in port_counts:
                    port_counts[port] += 1
                else:
                    port_counts[port] = 1
    return port_counts

def create_port_traffic_report(log_file, port_number):
    report_entries = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'^(.{6}) (\d\d:\d\d:\d\d).*SRC=(.+?) DST=(.+?) .*SPT=(.+?) DPT=' + f"({port_number})", line)
            if match:
                date, time, src_ip, dst_ip, src_port, dst_port = match.groups()
                report_entries.append((date, time, src_ip, dst_ip, src_port, dst_port))
    report_df = pd.DataFrame(report_entries, columns=['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False)


def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 10
    # Get data from records that show attempted invalid user login
    # Generate the CSV report
    return

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 11
    # Get all records that have the specified source IP address
    # Save all records to a plain text .log file
    return

if __name__ == '__main__':
    main()
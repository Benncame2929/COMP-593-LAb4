import re
import pandas as pd
from log_analysis_lib import get_file_path_from_cmd_line(1), filter_log_by_regex

def main():
    log_file = get_file_path_from_cmd_line()
    port_traffic = tally_port_traffic(log_file)
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_file, port)
    generate_invalid_user_report(log_file)
    log_records_from_source_ip(log_file, '220.195.35.40')

def tally_port_traffic(log_file):
    port_counts = {}
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'DPT=(\d+)', line)
            if match:
                port = match.group(1)
                port_counts[port] = port_counts.get(port, 0) + 1
    return port_counts

def generate_port_traffic_report(log_file, port_number):
    report_entries = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'^(.{6}) (\d\d:\d\d:\d\d).*SRC=(.+?) DST=(.+?) .*SPT=(.+?) DPT=' + f"({port_number})", line)
            if match:
                date, time, src_ip, dst_ip, src_port, dst_port = match.groups()
                report_entries.append((date, time, src_ip, dst_ip, src_port, dst_port))
    report_df = pd.DataFrame(report_entries, columns=['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False)

def generate_invalid_user_report(log_file):
    invalid_logins = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'^(.{6}) (\d\d:\d\d:\d\d).*Invalid user (\w+) from (.*)', line)
            if match:
                date, time, username, ip_address = match.groups()
                invalid_logins.append((date, time, username, ip_address))
    report_df = pd.DataFrame(invalid_logins, columns=['Date', 'Time', 'Username', 'IP Address'])
    report_df.to_csv('invalid_users.csv', index=False)

def log_records_from_source_ip(log_file, ip_address):
    matching_records = []
    with open(log_file, 'r') as file:
        for line in file:
            if f'SRC={ip_address}' in line:
                matching_records.append(line.strip())
    output_file_name = f'source_ip_{ip_address.replace(".", "_")}.log'
    with open(output_file_name, 'w') as output_file:
        for record in matching_records:
            output_file.write(record + '\n')

if __name__ == '__main__':
    main()

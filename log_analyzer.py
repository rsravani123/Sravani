import csv
import re
from collections import Counter, defaultdict


def parse_log_line(line):
    """
    Parses a single log line and extracts the IP address, endpoint, and status code.
    """
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(GET|POST|PUT|DELETE) (?P<endpoint>\S+) HTTP/1.1" (?P<status>\d+)'
    match = re.match(pattern, line)
    if match:
        return match.group("ip"), match.group("endpoint"), match.group("status")
    return None, None, None


def analyze_log(file_path):
    """
    Processes the log file and performs analysis: counts IP requests, endpoints, and suspicious activities.
    """
    ip_counter = Counter()
    endpoint_counter = Counter()
    error_counter = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            ip, endpoint, status = parse_log_line(line)
            if ip and endpoint:
                ip_counter[ip] += 1
                endpoint_counter[endpoint] += 1
                if status == "401":
                    error_counter[ip] += 1

    return ip_counter, endpoint_counter, error_counter


def write_to_csv_and_print(ip_counter, endpoint_counter, error_counter, output_path):
    """
    Writes analysis results to a CSV file and prints them to the terminal.
    """
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP Request Counts
        print(f"{'IP Address':<20} {'Request Count':<15}")
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counter.items():
            print(f"{ip:<20} {count:<15}")
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        most_accessed = endpoint_counter.most_common(1)
        print("\nMost Frequently Accessed Endpoint:")
        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint', 'Access Count'])
        if most_accessed:
            endpoint, count = most_accessed[0]
            print(f"{endpoint} (Accessed {count} times)")
            writer.writerow([endpoint, f"Accessed {count} times"])

        # Write Suspicious Activity
        print("\nSuspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Login Attempts':<15}")
        writer.writerow([])
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Login Attempts'])
        for ip, attempts in error_counter.items():
            if attempts > 10:  # Threshold for suspicious activity
                print(f"{ip:<20} {attempts:<15}")
                writer.writerow([ip, attempts])


if __name__ == "__main__":
    log_file_path = 'sample.log'
    output_file_path = 'output.csv'

    ip_counts, endpoint_counts, error_counts = analyze_log(log_file_path)
    write_to_csv_and_print(ip_counts, endpoint_counts, error_counts, output_file_path)

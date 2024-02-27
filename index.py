import argparse
import csv
from log_analyzer import LogEntry

def parse_arguments():
    parser = argparse.ArgumentParser(description="Log Analyzer Program")
    parser.add_argument("--filename", help="CSV file containing log data", required=True)
    return parser.parse_args()

def main():
    args = parse_arguments()
    filename = args.filename

    log_entries = []

    # Read data from the CSV file
    with open(filename, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            # Create LogEntry objects from CSV data
            log_entry = LogEntry(
                row['event_time'],
                row['internal_ip'],
                row['port_number'],
                row['protocol'],
                row['action'],
                row['rule_id'],
                row['source_ip'],
                country=row.get('country'),  # Providing default values for optional arguments
                country_name=row.get('country_name')
            )
            log_entries.append(log_entry)

    # Print information for the first five LogEntry objects
    for log_entry in log_entries[:5]:
        print("Date:", log_entry.event_time.strftime("%m/%d/%Y %H:%M %Z"), "in Eastern Time")
        print("Action:", log_entry.action)
        print("Source IP:", log_entry.source_ip)
        print("IPv4 Class:", log_entry.ipv4_class)
        print("Country Name:", log_entry.country_name)
        print()

if __name__ == "__main__":
    main()

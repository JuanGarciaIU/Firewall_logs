import argparse
import csv
from log_analyzer import LogEntry

def parse_arguments():
    parser = argparse.ArgumentParser(description="Log Analyzer Program")
    parser.add_argument("--filename","-f", help="CSV file containing log data", required=True)
    parser.add_argument("--action","-a", help="Actions preformed", choices=["head"], required=True)
    return parser.parse_args()

def print_head(log_entries):
  for log_entry in log_entries[:5]:
        print(log_entry.event_time.strftime("%m/%d/%Y %H:%M %Z"),",", log_entry.action,",", log_entry.source_ip, ",", log_entry.ipv4_class, ",", log_entry.country_name)


def main():

    args = parse_arguments()
    filename = args.filename

    log_entries = []

    with open(filename, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            log_entry = LogEntry(
                row['event_time'],
                row['internal_ip'],
                row['port_number'],
                row['protocol'],
                row['action'],
                row['rule_id'],
                row['source_ip'],
                country=row.get('country'), 
                country_name=row.get('country_name')
            )
            log_entries.append(log_entry)

    if action == "head":
        print_head(log_entries)

if __name__ == "__main__":
    main()

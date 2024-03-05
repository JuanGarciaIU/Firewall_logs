import argparse
import csv
from log_analyzer import LogEntry

def parse_arguments():
    parser = argparse.ArgumentParser(description="Log Analyzer Program")
    parser.add_argument("--filename","-f", help="CSV file containing log data", required=True)
    parser.add_argument("--action","-a", help="Actions preformed", choices=["head", "deny", "source"], required=True)
    parser.add_argument("--country","-c", help="Country code required")

    return parser.parse_args()

def print_head(log_entries):
  for log_entry in log_entries[:5]:
        print(log_entry.event_time.strftime("%m/%d/%Y %H:%M %Z"),",", log_entry.action,",", log_entry.source_ip, ",", log_entry.ipv4_class, ",", log_entry.country_name)

def deny_count(log_entries):
    denied_entries = [entry for entry in log_entries if entry.action == "Deny"]
    print(len(denied_entries), "log entries were denied.")

def country_count(log_entries, selected_country):
    country_entries = [entry for entry in log_entries if entry.country == selected_country]
    print(len(country_entries), "log entries match the country", selected_country)



def main():
    args = parse_arguments()
    filename = args.filename
    action = args.action
    selected_country = args.country


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
    elif action == "deny":
        deny_count(log_entries)
    elif action == "source":
        selected_country = args.country
        if selected_country:
            country_count(log_entries, selected_country)
        else:
            print("Please provide a 2-letter country code as a command line argument.")

if __name__ == "__main__":
    main()


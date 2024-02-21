from datetime import datetime

class LogEntry:
    def __init__(self, event_time, internal_ip, port_number, protocol, action, rule_id, source_ip, country=None, country_name=None):
        self.event_time = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S %Z')
        self.internal_ip = internal_ip
        self.port_number = port_number
        self.protocol = protocol
        self.action = action
        self.rule_id = rule_id
        self.source_ip = source_ip
        self.country = country
        self.country_name = country_name

    @property
    def ipv4_class(self):
        first_octet = int(self.source_ip.split('.')[0])

        if 1 <= first_octet <= 126:
            return 'A'
        elif 128 <= first_octet <= 191:
            return 'B'
        elif 192 <= first_octet <= 223:
            return 'C'
        elif 224 <= first_octet <= 239:
            return 'D'
        else:
            return 'Unknown'

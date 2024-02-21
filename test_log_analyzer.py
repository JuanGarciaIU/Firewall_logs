import unittest
from log_analyzer import LogEntry
from datetime import datetime


class TestLogEntry(unittest.TestCase):
    def test_event_time(self):
        Log_Entry = LogEntry("2022-01-01 08:29:25 UTC", "192.168.1.1", 80, "TCP", "ALLOW", "1234", "229.163.4.51", "US", "United States")
        self.assertEqual(Log_Entry.event_time.month, 1)
        self.assertEqual(Log_Entry.event_time.hour, 8)

    
    def test_ipv4(self):
        log_Entry1 = LogEntry("2022-01-01 08:29:25 UTC", "192.168.1.1", 80, "TCP", "ALLOW", "1234", "229.163.4.51", "US", "United States")
        log_Entry2 = LogEntry("2022-01-01 08:29:25 UTC", "192.168.1.1", 80, "TCP", "ALLOW", "1234", "173.205.219.112", "US", "United States")

        self.assertEqual(log_Entry1.ipv4_class, 'D')  
        self.assertEqual(log_Entry2.ipv4_class, 'B')




if __name__ == '__main__':
    unittest.main()
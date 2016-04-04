import os
import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from watchdog.events import FileSystemEventHandler
from pcap_parser import process_pcap_file

class PcapFileCreatedEventHandler(FileSystemEventHandler):
    """Watch for new Pcap Files in the directory where this script is running"""
    def on_created(self, event):
        initial_path = os.path.dirname(os.path.abspath(__file__))
        super(PcapFileCreatedEventHandler, self).on_created(event)
        if not event.is_directory:
            if event.src_path.endswith(".pcap"):
                print("The new PCAP file {} was detected. It is now being processed..."\
                    .format(event.src_path))
                process_pcap_file(initial_path+event.src_path[1:])
                

if __name__ == "__main__":            
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = PcapFileCreatedEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
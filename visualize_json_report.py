import os
import subprocess
from os.path import expanduser

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

class VisualizeJsonReport(Report):
    """Visualize data in json report file."""
    # Make file run last, after analysis has completed

    order = 3

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
			# Get home directory path
			home_path = expanduser("~")
			# Full path to json report file
        	report_path = os.path.join(self.reports_path, "report.json")
        	# Full path to application visualize_json_report
            script_path = os.path.join(home_path, ".cuckoo/visualize_json_report/run.py")
            # Full path to location to store html file created, same directory as report json
            new_file_path = os.path.join(self.reports_path, "report.html")
            
      		# Get choice from config file
        	choice = self.options['report_type']
        	print("The visulisation choice is {}".format(choice))

        	parameters = list()
        		
			# Visualize processes only
			if choice == int(1):
				print("Visualize porcesses only")
				parameters = ["/usr/bin/python3", script_path, "-f", new_file_path, "-fa", "-ra", "-na", report_path] 
			# Visualize processes and network
			elif choice == int(2):
				print("Visualize porcesses and network data")
				parameters = ["/usr/bin/python3", script_path, "-f", new_file_path, "-fa", "-ra", report_path]
			# Visualize processes and files
			elif choice == int(3):
				print("Visualize porcesses file data")
				parameters = ["/usr/bin/python3", script_path, "-f", new_file_path, "-na", "-ra", report_path]
			# Visualize processes and registry
			elif choice == int(4):
				print("Visualize porcesses and registry data")
				parameters = ["/usr/bin/python3", script_path, "-f", new_file_path, "-fa", "-na", report_path]
			# Visualize processes and registry
			else:
				print("Visualize porcesses only, this is the default mode")
				parameters = ["/usr/bin/python3", script_path, "-f", new_file_path, "-fa", "-ra", "-na", report_path]

			subprocess.call(parameters)

		except (UnicodeError, TypeError, IOError) as e:
			raise CuckooReportError("Failed to generate JSON report: %s" % e)
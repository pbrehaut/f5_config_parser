import os
from f5_config_parser.reports.virtual_server_reports import generate_virtual_server_report
from f5_config_parser.reports.base_network_report import generate_network_report
from f5_config_parser.reports.device_report import generate_device_report

# Input paths
INPUT_FILE = r"/path/to/your/f5_config_directory"
TAR_FILE = r"/path/to/your/f5_config_archive.tar"
OUTPUT_DIR = r"/path/to/your/output_directory"

# Extract base filename (without extension) from input file
base_filename = os.path.splitext(os.path.basename(INPUT_FILE))[0]

# Generate all reports with consistent naming
print(f"Generating reports for: {base_filename}\n")

vs_result = generate_virtual_server_report(
    input_file=INPUT_FILE,
    output_dir=OUTPUT_DIR,
    tar_file=TAR_FILE,
    output_filename=base_filename
)

device_result = generate_device_report(
    input_file=INPUT_FILE,
    output_dir=OUTPUT_DIR,
    output_filename=base_filename
)

network_result = generate_network_report(
    input_file=INPUT_FILE,
    output_dir=OUTPUT_DIR,
    output_filename=base_filename
)

print("\nAll reports generated successfully!")
print(f"\nVirtual Server Reports:")
for key, path in vs_result.items():
    print(f"  {key}: {path}")

print(f"\nDevice Report:")
for key, path in device_result.items():
    print(f"  {key}: {path}")

print(f"\nNetwork Report:")
for key, path in network_result.items():
    print(f"  {key}: {path}")
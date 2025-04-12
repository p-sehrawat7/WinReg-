import tkinter as tk
from tkinter import filedialog
import os
import winreg
import subprocess

# Function to extract registry value from a specific key
def get_registry_value(key, sub_key, value_name):
    try:
        registry_key = winreg.OpenKey(key, sub_key, 0, winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, value_name)
        winreg.CloseKey(registry_key)
        return value
    except FileNotFoundError:
        print(f"Registry key not found: {sub_key}")
    except PermissionError:
        print(f"Permission denied to access registry key: {sub_key}")
    except OSError as e:
        print(f"Windows error occurred: {e}")
    return None

# Function to extract logging information
def extract_logging_info(selected_logs):
    logging_info = {}
    registry_paths = {
        "Application": r'SYSTEM\CurrentControlSet\Services\EventLog\Application',
        "System": r'SYSTEM\CurrentControlSet\Services\EventLog\System',
        "Security": r'SYSTEM\CurrentControlSet\Services\EventLog\Security',
        "Setup": r'SYSTEM\CurrentControlSet\Services\EventLog\Setup',
        "Forwarded Events": r'SYSTEM\CurrentControlSet\Services\EventLog\ForwardedEvents',
    }

    for log_name in selected_logs:
        sub_key = registry_paths.get(log_name)
        if sub_key:
            value = get_registry_value(winreg.HKEY_LOCAL_MACHINE, sub_key, 'File')
            if value:
                # Resolve %SystemRoot% to the actual system root path
                value = value.replace("%SystemRoot%", os.environ.get("SystemRoot", "C:\\Windows"))
                logging_info[log_name] = value
            else:
                print(f"Failed to retrieve value for log: {log_name}")

    return logging_info

# Function to export event logs using wevtutil
def export_event_log(log_name, export_path):
    try:
        # Check if the file exists and delete it
        if os.path.exists(export_path):
            os.remove(export_path)
            print(f"Deleted existing file: {export_path}")
        
        # Use wevtutil to export the event log
        command = f'wevtutil epl {log_name} "{export_path}"'
        subprocess.run(command, check=True, shell=True)
        print(f"Exported {log_name} log to {export_path}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to export {log_name} log: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while exporting {log_name}: {e}")

# Function to browse and select directory
def browse_directory(directory_var):
    folder_selected = filedialog.askdirectory()
    directory_var.set(folder_selected)

# Function to save exported logs to file
def save_to_file(directory, filename, data):
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, filename)

    with open(file_path, 'w') as file:
        for log_name, log_file in data.items():
            export_path = os.path.join(directory, f"{log_name}.evtx")
            file.write(f'Log Path: {log_name}\n')
            file.write(f'Log File: {log_file}\n')
            
            # Export the event log
            export_event_log(log_name, export_path)
            file.write(f'Exported Log File: {export_path}\n\n')
    print(f"Data written to file: {file_path}")

# GUI: Function to update selected logs list
def update_selected_logs(log_name, selected_logs):
    if log_name in selected_logs:
        selected_logs.remove(log_name)
    else:
        selected_logs.append(log_name)

# GUI main function
def main():
    # Initialize the main Tkinter window
    root = tk.Tk()
    root.title("Windows Event Log Exporter")
    root.geometry("600x600")

    # Frame for log checkboxes
    logs_frame = tk.LabelFrame(root, text="Select Logs to Export")
    logs_frame.pack(fill="x", padx=10, pady=5)

    selected_logs = []

    # Add checkboxes for log selection
    tk.Checkbutton(logs_frame, text="Application",
                   command=lambda: update_selected_logs("Application", selected_logs)).pack(anchor="w")
    tk.Checkbutton(logs_frame, text="System",
                   command=lambda: update_selected_logs("System", selected_logs)).pack(anchor="w")
    tk.Checkbutton(logs_frame, text="Security",
                   command=lambda: update_selected_logs("Security", selected_logs)).pack(anchor="w")
    tk.Checkbutton(logs_frame, text="Setup",
                   command=lambda: update_selected_logs("Setup", selected_logs)).pack(anchor="w")
    tk.Checkbutton(logs_frame, text="Forwarded Events",
                   command=lambda: update_selected_logs("Forwarded Events", selected_logs)).pack(anchor="w")

    # Frame for output directory selection
    output_frame = tk.LabelFrame(root, text="Output Directory")
    output_frame.pack(fill="x", padx=10, pady=5)

    output_dir_var = tk.StringVar()

    tk.Entry(output_frame, textvariable=output_dir_var, width=50).pack(side="left", padx=5, pady=5)
    tk.Button(output_frame, text="Browse", command=lambda: browse_directory(output_dir_var)).pack(side="left", padx=5)

    # Text area for log messages
    log_area = tk.Text(root, height=10, wrap="word")
    log_area.pack(fill="both", padx=10, pady=5, expand=True)

    # Start export button
    def start_export():
        if selected_logs:
            logging_info = extract_logging_info(selected_logs)
            if logging_info:
                save_to_file(output_dir_var.get(), 'logging_info.txt', logging_info)
                log_area.insert(tk.END, f"Logging information has been saved to '{os.path.join(output_dir_var.get(), 'logging_info.txt')}'.\n")
            else:
                log_area.insert(tk.END, "No logs selected or found.\n")
        else:
            log_area.insert(tk.END, "No logs selected.\n")

    # Add the Export Logs button to the GUI
    export_button = tk.Button(root, text="Export Logs", command=start_export)
    export_button.pack(pady=10)

    root.mainloop()

# Run the application
if __name__ == "__main__":
    main()
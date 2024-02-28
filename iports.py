# importer.py

def import_from_file(file_name):
    with open(file_name, 'r') as file:
        module_names = file.read().splitlines()

    # Import the modules listed in the file
    for module_name in module_names:
        try:
            __import__(module_name)
        except ImportError as e:
            print(f"Error importing module {module_name}: {e}")

# Usage
import_from_file('requirements.txt')

# Now you can use the imported modules
# For example:
import os
print(os.getcwd())

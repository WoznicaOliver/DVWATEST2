import json
import sys

# Map Psalm SARIF level to numeric security-severity and psalmSeverity
SEVERITY_MAPPING = {
    "error": {"security_severity": 8.5, "psalmSeverity": "high"},
    "warning": {"security_severity": 5.5, "psalmSeverity": "medium"},
    "note": {"security_severity": 2.0, "psalmSeverity": "low"},
    "none": {"security_severity": 0.0, "psalmSeverity": "none"}
}

def enhance_sarif(sarif_file_path):
    try:
        with open(sarif_file_path, 'r') as file:
            sarif_data = json.load(file)

        for run in sarif_data.get("runs", []):
            for result in run.get("results", []):
                level = result.get("level", "none").lower()

                #try to map, default to "none"
                mapping = SEVERITY_MAPPING.get(level, {"security_severity": 0.0, "psalmSeverity": "none"})

                # Keep original level, just add kind and properties
                result["kind"] = "open"
                if "properties" not in result:
                    result["properties"] = {}
                result["properties"]["security-severity"] = str(mapping["security_severity"])
                result["properties"]["psalmSeverity"] = mapping["psalmSeverity"]

        output_path = "psalm_mapped.sarif"
        with open(output_path, 'w') as file:
            json.dump(sarif_data, file, indent=2)

        print(f"mapped SARIF file saved to: {output_path}")

    except Exception as e:
        print(f"Error processing SARIF file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python Psalm_SARIF_Mapper.py <path_to_sarif_file>")
        sys.exit(1)

    enhance_sarif(sys.argv[1])

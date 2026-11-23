
import argparse
import csv
import json
import logging
import os
import sys
import zipfile

from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv


# --------------------------------------------------
# LOGGING CONFIGURATION
# --------------------------------------------------

logging.basicConfig(
    filename="errors.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    encoding="utf-8"
)


# --------------------------------------------------
# ENVIRONMENT VARIABLES
# --------------------------------------------------

load_dotenv()

API_KEY = os.getenv("WEATHER_API_KEY")

WEATHER_URL = "https://api.weatherapi.com/v1/current.json"


# --------------------------------------------------
# COMMAND-LINE ARGUMENTS
# --------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Enrich CRITICAL security logs with live weather."
    )

    parser.add_argument(
        "log_file",
        help="Path to the input CSV log file"
    )

    return parser.parse_args()


# --------------------------------------------------
# READ AND FILTER SECURITY LOGS
# --------------------------------------------------

def read_critical_logs(file_path):
    """Read a CSV file and return CRITICAL security alerts."""

    logging.info("Reading input CSV: %s", file_path)

    critical_logs = []

    with open(
        file_path,
        mode="r",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError(
                "CSV file is empty or missing headers."
            )

        required = {
            "timestamp",
            "level",
            "source",
            "message",
            "location"
        }

        missing = required - set(reader.fieldnames)

        if missing:
            raise ValueError(
                f"Missing CSV columns: {sorted(missing)}"
            )

        for row in reader:

            if None in row or any(
                value is None for value in row.values()
            ):
                raise ValueError(
                    "Malformed CSV row detected."
                )

            if row["level"] == "CRITICAL":
                critical_logs.append(row)

    logging.info(
        "CSV processed successfully. Found %d CRITICAL alerts.",
        len(critical_logs)
    )

    return critical_logs


# --------------------------------------------------
# FETCH WEATHER DATA
# --------------------------------------------------

def get_weather(city):
    """Fetch weather information and log API activity."""

    if not API_KEY or API_KEY == "YOUR_ACTUAL_API_KEY_HERE":
        logging.error(
            "Weather API key is missing or not configured."
        )

        raise ValueError(
            "WEATHER_API_KEY is missing or not configured."
        )

    params = {
        "key": API_KEY,
        "q": city,
        "aqi": "no"
    }

    logging.info(
        "Requesting weather data for %s",
        city
    )

    try:
        response = requests.get(
            WEATHER_URL,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        try:
            data = response.json()

        except ValueError as error:
            logging.error(
                "Invalid JSON returned for %s",
                city
            )

            raise ValueError(
                f"Weather API returned invalid JSON for {city}"
            ) from error

        try:
            current = data["current"]

            temperature = current["temp_c"]

            condition = current["condition"]["text"]

            if (
                isinstance(temperature, bool)
                or not isinstance(temperature, (int, float))
            ):
                raise ValueError(
                    "Temperature must be numeric."
                )

            if not isinstance(condition, str):
                raise ValueError(
                    "Weather condition must be text."
                )

        except (KeyError, TypeError, ValueError) as error:
            logging.error(
                "Invalid weather response structure for %s: %s",
                city,
                error
            )

            raise ValueError(
                f"Invalid weather response data for {city}"
            ) from error

        logging.info(
            "Weather API success for %s",
            city
        )

        return {
            "temperature_c": temperature,
            "weather_condition": condition
        }

    except requests.exceptions.HTTPError as error:
        status = (
            error.response.status_code
            if error.response is not None
            else "unknown"
        )

        if status in (401, 403):
            logging.error(
                "Weather API authentication failed for %s (HTTP %s)",
                city,
                status
            )

            raise ValueError(
                "Weather API authentication failed. Check your API key."
            ) from error

        logging.error(
            "Weather API HTTP failure for %s: %s",
            city,
            status
        )

        raise RuntimeError(
            f"Weather API HTTP error {status} for {city}"
        ) from error

    except requests.exceptions.RequestException as error:
        logging.error(
            "Weather API network failure for %s: %s",
            city,
            type(error).__name__
        )

        raise RuntimeError(
            f"Weather API request failed for {city}: "
            f"{type(error).__name__}"
        ) from error


# --------------------------------------------------
# ENRICH CRITICAL LOGS
# --------------------------------------------------

def enrich_logs(critical_logs):
    """Add live weather information to CRITICAL alerts."""

    enriched_logs = []

    weather_cache = {}

    for log in critical_logs:

        city = log["location"].strip()

        if not city:
            raise ValueError(
                "A CRITICAL log has an empty location."
            )

        if city not in weather_cache:

            print(f"Fetching weather for {city}...")

            weather_cache[city] = get_weather(city)

        enriched_log = {
            **log,
            **weather_cache[city]
        }

        enriched_logs.append(enriched_log)

    return enriched_logs


# --------------------------------------------------
# EXPORT CSV REPORT
# --------------------------------------------------

def export_to_csv(enriched_logs, timestamp):
    """Export enriched alerts to a timestamped CSV."""

    filename = f"report_{timestamp}.csv"

    fieldnames = [
        "timestamp",
        "level",
        "source",
        "message",
        "location",
        "temperature_c",
        "weather_condition"
    ]

    with open(
        filename,
        mode="w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(enriched_logs)

    print(f"CSV report created: {filename}")

    logging.info(
        "CSV report created: %s",
        filename
    )

    return filename


# --------------------------------------------------
# EXPORT JSON REPORT
# --------------------------------------------------

def export_to_json(enriched_logs, timestamp):
    """Export enriched alerts to a timestamped JSON."""

    filename = f"report_{timestamp}.json"

    with open(
        filename,
        mode="w",
        encoding="utf-8"
    ) as file:

        json.dump(
            enriched_logs,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(f"JSON report created: {filename}")

    logging.info(
        "JSON report created: %s",
        filename
    )

    return filename


# --------------------------------------------------
# CREATE ZIP ARCHIVE
# --------------------------------------------------

def create_zip_archive(csv_file, json_file, timestamp):
    """Package CSV and JSON reports into a ZIP archive."""

    zip_filename = f"output_{timestamp}.zip"

    logging.info(
        "Starting ZIP archive creation: %s",
        zip_filename
    )

    with zipfile.ZipFile(
        zip_filename,
        mode="w",
        compression=zipfile.ZIP_DEFLATED
    ) as archive:

        archive.write(
            csv_file,
            arcname=Path(csv_file).name
        )

        archive.write(
            json_file,
            arcname=Path(json_file).name
        )

    logging.info(
        "ZIP archive created successfully: %s",
        zip_filename
    )

    print(f"ZIP archive created: {zip_filename}")

    return zip_filename


# --------------------------------------------------
# VERIFY ZIP ARCHIVE
# --------------------------------------------------

def verify_zip_archive(zip_filename):
    """Verify ZIP integrity and expected report contents."""

    with zipfile.ZipFile(
        zip_filename,
        mode="r"
    ) as archive:

        names = archive.namelist()

        if len(names) != 2:
            raise ValueError(
                "ZIP archive must contain exactly two files."
            )

        if not any(
            name.endswith(".csv") for name in names
        ):
            raise ValueError(
                "CSV report missing from ZIP archive."
            )

        if not any(
            name.endswith(".json") for name in names
        ):
            raise ValueError(
                "JSON report missing from ZIP archive."
            )

        bad_file = archive.testzip()

        if bad_file is not None:
            raise ValueError(
                f"ZIP integrity check failed for {bad_file}"
            )

    logging.info(
        "ZIP archive verified successfully: %s",
        zip_filename
    )

    return True


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():

    logging.info(
        "========== Script started =========="
    )

    try:
        args = parse_arguments()

        print(
            "Starting Python Log + Weather Automation..."
        )

        critical_logs = read_critical_logs(
            args.log_file
        )

        print(
            f"Found {len(critical_logs)} CRITICAL alerts."
        )

        if not critical_logs:
            logging.warning(
                "No CRITICAL alerts found in input file."
            )

        enriched_logs = enrich_logs(
            critical_logs
        )

        for log in enriched_logs:

            print("-" * 40)

            print(
                f"Timestamp: {log['timestamp']}"
            )

            print(
                f"Source: {log['source']}"
            )

            print(
                f"Message: {log['message']}"
            )

            print(
                f"Location: {log['location']}"
            )

            print(
                f"Temperature: {log['temperature_c']} C"
            )

            print(
                f"Condition: {log['weather_condition']}"
            )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        csv_file = export_to_csv(
            enriched_logs,
            timestamp
        )

        json_file = export_to_json(
            enriched_logs,
            timestamp
        )

        zip_file = create_zip_archive(
            csv_file,
            json_file,
            timestamp
        )

        verify_zip_archive(
            zip_file
        )

        print(
            "\nReports generated successfully!"
        )

        print(f"CSV: {csv_file}")

        print(f"JSON: {json_file}")

        print(f"ZIP: {zip_file}")

        logging.info(
            "Script completed successfully."
        )

        return 0

    except (
        OSError,
        UnicodeError,
        csv.Error,
        ValueError,
        RuntimeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile
    ) as error:

        logging.error(
            "Script failed: %s",
            type(error).__name__
        )

        print(
            f"ERROR: {error}",
            file=sys.stderr
        )

        return 1

    finally:
        logging.info(
            "========== Script ended =========="
        )


# --------------------------------------------------
# PROGRAM ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())

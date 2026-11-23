# Python Log + Weather Automation Capstone

## Project Overview

This Python application reads a CSV file containing security events, filters CRITICAL alerts, retrieves current weather information for each alert location, and generates timestamped CSV and JSON reports.

It also records application activity in `errors.log` and automatically creates a ZIP archive containing both generated reports.

## Technologies

- Python 3
- requests
- python-dotenv
- WeatherAPI.com
- Python standard-library modules: csv, json, logging, argparse, datetime, pathlib, and zipfile

## Setup

1. Create and activate a Python virtual environment.
2. Install dependencies:

   `python -m pip install -r requirements.txt`

3. Open `.env` and replace `YOUR_API_KEY_HERE` with a valid WeatherAPI key.

## Run the Application

`python main.py logs.csv`

## Expected Results

The application identifies CRITICAL security events and creates:

- `report_<timestamp>.csv`
- `report_<timestamp>.json`
- `output_<timestamp>.zip`
- `errors.log`

The ZIP archive contains the generated CSV and JSON reports.

## Error Handling

The application handles missing CSV files, malformed CSV data, missing or invalid API credentials, HTTP errors, network failures, invalid JSON responses, and report-generation failures.

## Security

The submission includes a dummy `.env` file. Real API credentials must not be shared or committed to source control.

# Heimdal Real-time Network Monitoring System

Heimdal is a real-time network monitoring and anomaly detection system that transforms static pcap file analysis into live network traffic monitoring. As the local edge component of the Cortexa hybrid architecture, Heimdal continuously monitors network behavior, maintains local behavioral baselines, detects anomalies, and forwards anonymized metadata to the Asgard cloud platform for global threat intelligence.

## Project Structure

```
heimdal/
├── heimdal/                    # Main package directory
│   ├── __init__.py
│   ├── main.py                 # Application entry point
│   ├── models.py               # Core data models
│   ├── interfaces.py           # Component interfaces
│   ├── capture/                # Packet capture components
│   │   └── __init__.py
│   ├── analysis/               # Real-time analysis components
│   │   └── __init__.py
│   ├── baseline/               # Baseline management components
│   │   └── __init__.py
│   ├── anomaly/                # Anomaly detection components
│   │   └── __init__.py
│   ├── communication/          # Asgard cloud communication
│   │   └── __init__.py
│   ├── config/                 # Configuration management
│   │   ├── __init__.py
│   │   └── manager.py          # Configuration manager implementation
│   └── logging/                # Logging and diagnostics
│       └── __init__.py
├── config/                     # Configuration files
│   ├── heimdal.yaml           # YAML configuration template
│   └── heimdal.json           # JSON configuration template
├── requirements.txt            # Python dependencies
├── setup.py                   # Package setup script
└── README.md                  # This file
```

## Features

- **Real-time Packet Capture**: Continuous monitoring of live network traffic
- **Behavioral Analysis**: Device fingerprinting and behavior pattern extraction
- **Anomaly Detection**: Real-time comparison against learned baselines
- **Cloud Integration**: Bidirectional communication with Asgard platform
- **Data Anonymization**: Privacy-preserving metadata transmission
- **Configurable Thresholds**: Tunable anomaly detection parameters
- **Comprehensive Logging**: Detailed system diagnostics and monitoring

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Install the package:
```bash
pip install -e .
```

## Configuration

Heimdal supports both YAML and JSON configuration files. Copy and customize one of the templates:

```bash
cp config/heimdal.yaml /etc/heimdal/config.yaml
# or
cp config/heimdal.json /etc/heimdal/config.json
```

Key configuration sections:
- **capture**: Packet capture settings
- **analysis**: Real-time analysis parameters
- **anomaly_detection**: Detection thresholds and algorithms
- **baseline**: Baseline management settings
- **asgard**: Cloud communication configuration
- **logging**: System logging configuration

## Usage

### Command Line

Run Heimdal with default configuration:
```bash
heimdal
```

Run with custom configuration:
```bash
heimdal --config /path/to/config.yaml
```

Validate configuration:
```bash
heimdal --validate-config --config /path/to/config.yaml
```

### Python API

```python
from heimdal.main import HeimdallApplication

# Create and start the application
app = HeimdallApplication("config/heimdal.yaml")
app.start()

# Keep running until stopped
app.run()
```

## Requirements

- Python 3.8 or higher
- Root privileges for packet capture
- Network interface access
- Sufficient disk space for baseline storage and logs

### System Dependencies

- **scapy**: Packet capture and analysis
- **pyyaml**: YAML configuration support
- **requests**: HTTP communication with Asgard
- **python-dateutil**: Date/time handling

### Optional Dependencies

- **psutil**: System performance monitoring
- **geoip2**: IP geolocation (requires MaxMind database)
- **cryptography**: Enhanced security features

## Architecture

Heimdal follows a modular architecture with clear interfaces between components:

1. **Packet Capture Engine**: Captures live network packets
2. **Real-time Analyzer**: Extracts behavioral features from packets
3. **Baseline Manager**: Maintains device behavioral baselines
4. **Anomaly Detector**: Compares behavior against baselines
5. **Asgard Communicator**: Handles cloud communication
6. **Configuration Manager**: Manages system configuration

## Development Status

This project is currently in development. The core interfaces and data models have been established, and individual components are being implemented according to the specification.

## License

MIT License - see LICENSE file for details.

## Support

For support and documentation, visit: https://docs.cortexa.ai/heimdal
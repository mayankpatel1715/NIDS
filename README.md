# Network Intrusion Detection System (NIDS)

A Python-based network intrusion detection system that captures and analyzes network packets to detect potential security threats.

## Features

- Real-time packet capture from network interfaces
- Offline analysis of PCAP files
- Feature extraction from network packets
- Configurable logging and statistics reporting
- Command-line interface for easy operation

## Project Structure

```
NIDS/
├── config/                 # Configuration files
│   └── settings.json       # Main configuration file
├── logs/                   # Log files (created at runtime)
├── src/                    # Source code
│   ├── feature_extractor/  # Feature extraction modules
│   │   ├── capture/        # Packet capture functionality
│   │   └── features/       # Feature extraction algorithms
│   └── ...                 # Other modules
├── venv/                   # Virtual environment (not tracked in git)
├── .gitignore              # Git ignore file
├── main.py                 # Main application entry point
├── README.md               # This file
├── Requirements.txt        # Python dependencies
└── setup_env.sh            # Environment setup script
```

## Requirements

- Python 3.8+
- Scapy 2.5.0+
- Other dependencies listed in Requirements.txt

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/NIDS.git
   cd NIDS
   ```

2. Set up the virtual environment:
   ```bash
   ./setup_env.sh
   ```
   
   Or manually:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r Requirements.txt
   ```

## Usage

### List available network interfaces:
```bash
python main.py -l
```

### Live capture from a network interface:
```bash
python main.py -i eth0 -m live
```

### Read from a PCAP file:
```bash
python main.py -f capture.pcap -m offline
```

### Use a custom configuration file:
```bash
python main.py -i eth0 -c config/custom_settings.json
```

### Enable verbose output:
```bash
python main.py -i eth0 -v
```

### Apply a BPF filter:
```bash
python main.py -i eth0 -b "tcp port 80"
```

### Save extracted features to a file:
```bash
python main.py -i eth0 -o features.csv
```

## Configuration

The system can be configured through the `config/settings.json` file. Key configuration options include:

- **logging**: Configure log level, format, and output destinations
- **capture**: Set default interface, filters, and capture options
- **features**: Enable/disable feature extraction modules
- **system**: Configure system-wide settings like statistics reporting interval

## License

[MIT License](LICENSE)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

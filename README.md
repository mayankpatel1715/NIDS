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
- Root/Administrator privileges for live packet capture

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

### Important Note on Permissions

**Live packet capture requires root/administrator privileges** because it accesses network interfaces at a low level:

- On Linux/macOS: Use `sudo` before your commands
- On Windows: Run your command prompt or PowerShell as Administrator

### List available network interfaces:
```bash
sudo python main.py -l
```

### Live capture from a network interface:
```bash
sudo python main.py -i eth0 -m live
```

### Read from a PCAP file (does not require root privileges):
```bash
python main.py -f capture.pcap -m offline
```

### Use a custom configuration file:
```bash
sudo python main.py -i eth0 -c config/custom_settings.json
```

### Enable verbose output:
```bash
sudo python main.py -i eth0 -v
```

### Apply a BPF filter:
```bash
sudo python main.py -i eth0 -b "tcp port 80"
```

### Save extracted features to a file:
```bash
sudo python main.py -i eth0 -o features.csv
```

## Troubleshooting

### Permission Denied Error
If you see an error like:
```
Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root!
```
This means you need to run the command with `sudo` (on Linux/macOS) or as Administrator (on Windows).

### No Packets Captured
- Verify you're using the correct interface name
- Check that your filter isn't too restrictive
- Ensure there is actual network traffic on the interface
- Try running with the `-v` flag for verbose output

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


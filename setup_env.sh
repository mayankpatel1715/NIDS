#!/bin/bash
# Setup script for NIDS virtual environment

# Exit on error
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Setting up NIDS virtual environment...${NC}"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
else
    echo -e "${YELLOW}Virtual environment already exists.${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install requirements
echo -e "${YELLOW}Installing required packages...${NC}"
pip install --upgrade pip
pip install -r Requirements.txt

echo -e "${GREEN}Setup complete!${NC}"
echo -e "${YELLOW}To activate the virtual environment, run:${NC}"
echo -e "${GREEN}source venv/bin/activate${NC}"
echo -e "${YELLOW}To deactivate, run:${NC}"
echo -e "${GREEN}deactivate${NC}" 
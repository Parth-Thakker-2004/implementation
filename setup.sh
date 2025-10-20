#!/bin/bash

echo "System Log Anomaly Detector - Setup Script"
echo "=========================================="

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Error: UV package manager is not installed."
    echo "Please install UV first: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi

echo "✓ UV package manager found"

# Install dependencies
echo "Installing dependencies..."
uv sync

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "✗ Failed to install dependencies"
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✓ .env file created"
    echo ""
    echo "⚠️  IMPORTANT: Please edit the .env file and add your Google Gemini API key!"
    echo "   Get your API key from: https://makersuite.google.com/app/apikey"
    echo ""
else
    echo "✓ .env file already exists"
fi

echo ""
echo "Setup complete! You can now run the application with:"
echo "  uv run main.py"
echo ""
echo "Don't forget to:"
echo "1. Add your Google Gemini API key to the .env file"
echo "2. Prepare your system log CSV file"
echo ""
echo "For testing, you can use the included sample_system_logs.csv file"
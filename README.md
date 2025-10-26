# Bit-Cli

Bit is a fast, lightweight version control system designed for modern development workflows. With an intuitive CLI and powerful features, Bit helps you track changes, collaborate with others, and maintain clean project history.

https://bit-front-end.vercel.app

Disclaimer:
Bit is currently in its early stages of development. While it includes many powerful features, please be aware that the project is not yet fully stable and may contain bugs or incomplete functionality. Use it at your own discretion, and feel free to report issues or contribute to its improvement.

## ✨ Features

- 🔄 Simple, Git-like commands
- 🚀 Blazing fast performance
- 🔒 Built-in security with SSL/TLS support
- 📦 Cross-platform (Windows, Linux)
- 📡 Remote repository support
- 🔍 Easy-to-read commit history

## 📦 Installation

### Windows
1. Download the latest `bit-windows.zip` from the releases page
2. Extract the ZIP file to a permanent location (e.g., `C:\Bit`)
3. Add Bit to your system PATH:
   - Press `Win + R`, type `sysdm.cpl` and press Enter
   - Go to Advanced → Environment Variables
   - Under System Variables, find and select "Path", then click Edit
   - Click New and add the full path to the extracted folder (e.g., `C:\Bit`)
   - Click OK on all windows to save
4. Open a new Command Prompt and verify with:
   ```cmd
   bit help

### Linux (AppImage)
```bash
# Make executable
chmod +x Bit-x86_64.AppImage

# Run directly
./Bit-x86_64.AppImage help

# Or move to PATH for global access
sudo mv Bit-x86_64.AppImage /usr/local/bin/bit
```

### Pre-Built Packages
#### Arch Linux
```bash
# Install pre-built package
sudo pacman -U bit-1.0.0-1-x86_64.pkg.tar.zst

# Or build from PKGBUILD
makepkg -si
```

### Build from Source
#### Install Dependencies
##### Debian/Ubuntu
```bash
sudo apt install build-essential libcurl4-openssl-dev zlib1g-dev libjson-c-dev
```

#### Build
```bash
make
sudo make install  # Optional: install system-wide
```

## 🛠️ Usage

### Initialize a New Repository
```bash
bit init
```

### Stage Changes
```bash
bit add .
```

### Commit Changes
```bash
bit commit -m "Initial commit" -a "Author" -e "Email"
```

### Clone a Remote Repository
```bash
bit clone <share token here>
```

### Push Changes
```bash
bit push
```

## 🚀 Contributing
Contributions are always welcome! If you'd like to contribute to Bit, follow these steps:
1. Fork the repository.
2. Create a new branch.
3. Make your changes and commit them.
4. Push to your branch and create a pull request.

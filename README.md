# Bit-Cli

Bit is a fast, lightweight version control system designed for modern development workflows. With an intuitive CLI and powerful features, Bit helps you track changes, collaborate with others, and maintain clean project history.

## ✨ Features

- 🔄 Simple, Git-like commands
- 🚀 Blazing fast performance
- 🔒 Built-in security with SSL/TLS support
- 📦 Cross-platform (Windows, Linux, macOS)
- 📡 Remote repository support
- 🔍 Easy-to-read commit history

## 📦 Installation

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
bit commit -m "Initial commit"
```

### Clone a Remote Repository
```bash
bit clone https://example.com/repo.git
```

### Push Changes
```bash
bit push origin main
```

## 🚀 Contributing
Contributions are always welcome! If you'd like to contribute to Bit, follow these steps:
1. Fork the repository.
2. Create a new branch.
3. Make your changes and commit them.
4. Push to your branch and create a pull request.

## 📝 License
This project is not yet licensed. For inquiries about usage, please contact the repository owner.

---

Thank you for checking out Bit! If you have any questions or suggestions, feel free to open an issue or reach out directly.

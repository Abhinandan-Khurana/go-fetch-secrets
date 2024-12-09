# Go-Fetch-Secrets

🔍 **Go-Fetch-Secrets** is an advanced secret scanning tool designed to identify sensitive information, such as API keys and tokens, within your given urls.
Built using Golang, this tool is efficient and easy to use, making it essential for developers who want to enhance their security posture.

## Features

- **Pattern Matching**: Detects a wide range of secret formats with customizable regex patterns.
- **Multi-threaded Scanning**: Runs scans in parallel to speed up the process.
- **Various Output Formats**: Supports plain text, JSON, and CSV formats for easy integration with CI/CD pipelines.
- **Colorful Console Output**: Provides colorful feedback in the terminal for a better user experience.
- **Silent Mode**: Perform scans quietly without additional console output.

## Direct Installation

```bash
go install -v github.com/Abhinandan-Khurana/go-fetch-secrets@latest
```

## Installation

```bash
git clone https://github.com/Abhinandan-Khurana/go-fetch-secrets.git
cd go-fetch-secrets
go build
```

## Usage

```bash
# Run a scan with output in JSON format
go run main.go --format json --list your_file.txt

# Run a silent scan
go run main.go --format json --silent --list your_file.txt
```

## Configuration

Customize the secret patterns by modifying the `patterns.json` file to suit your project's specific needs. You can add, remove, or refine the regex patterns for better accuracy.

## Contributing

Contributions are welcome! If you find a bug or have suggestions for new features, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created by [Abhinandan Khurana](https://github.com/Abhinandan-Khurana)

---

Feel free to reach out for any queries or feedback. Happy scanning!

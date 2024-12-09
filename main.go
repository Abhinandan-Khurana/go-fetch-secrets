package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/sync/semaphore"
)

type Pattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// PatternsJSON represents the structure of patterns.json
type PatternsJSON map[string]string

type Result struct {
	Type     string
	Data     string
	URL      string
	TimeUsed time.Duration
}

type Config struct {
	patterns     []Pattern
	urls         []string
	threads      int64
	colorless    bool
	silent       bool
	outputFile   string
	outputFormat string
	foundSecrets sync.Map
	sem          *semaphore.Weighted
}

// ResultFormatter interface for different output formats
type ResultFormatter interface {
	FormatResult(result Result) string
	FileExtension() string
}

// Text formatter
type TextFormatter struct{}

func (f TextFormatter) FormatResult(result Result) string {
	return fmt.Sprintf("[+] Type: %s, Data: %s, URL: %s (Found in: %s)",
		result.Type, result.Data, result.URL, result.TimeUsed)
}

func (f TextFormatter) FileExtension() string {
	return "txt"
}

type JSONOutput struct {
	Type     string        `json:"type"`
	Data     string        `json:"data"`
	URL      string        `json:"url"`
	Duration time.Duration `json:"duration"`
}

// JSON formatter

type JSONFormatter struct{}

func (f JSONFormatter) FormatResult(result Result) string {
	output := struct {
		Type     string        `json:"type"`
		Data     string        `json:"data"`
		URL      string        `json:"url"`
		Duration time.Duration `json:"duration"`
	}{
		Type:     result.Type,
		Data:     result.Data,
		URL:      result.URL,
		Duration: result.TimeUsed,
	}
	jsonData, _ := json.Marshal(output)
	return string(jsonData)
}

func (f JSONFormatter) FileExtension() string {
	return "json"
}

// CSV formatter
type CSVFormatter struct{}

func (f CSVFormatter) FormatResult(result Result) string {
	return fmt.Sprintf("%s,%s,%s,%s",
		result.Type,
		result.Data,
		result.URL,
		result.TimeUsed)
}

func (f CSVFormatter) FileExtension() string {
	return "csv"
}

func getFormatter(format string) ResultFormatter {
	switch strings.ToLower(format) {
	case "json":
		return JSONFormatter{}
	case "csv":
		return CSVFormatter{}
	default:
		return TextFormatter{}
	}
}

func printHelp() {
	helpText := `
Go-Fetch-Secrets - Advanced Secret Scanner

Usage:
    go run main.go [options]

Options:
    --list      <file>    File containing list of URLs (required)
    --threads   <number>  Number of concurrent threads (default: 10)
    --colorless           Disable colored output
    --output    <file>    Output file to write results
    --format    <format>  Output format: txt, json, csv (default: txt)
    --silent              Suppress banner and status messages
    --help                Show this help message

Example:
    go run main.go --list urls.txt --threads 20 --format json --output results.json
    go run main.go --list urls.txt --silent --format csv --output results.csv

Note:
    Make sure patterns.json exists in the same directory.
`
	fmt.Println(helpText)
}

func printBanner() {
	banner := `
    ░██████╗░░█████╗░  ███████╗███████╗████████╗░█████╗░██╗░░██╗
    ██╔════╝░██╔══██╗  ██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║░░██║
    ██║░░██╗░██║░░██║  █████╗░░█████╗░░░░░██║░░░██║░░╚═╝███████║
    ██║░░╚██╗██║░░██║  ██╔══╝░░██╔══╝░░░░░██║░░░██║░░██╗██╔══██║
    ╚██████╔╝╚█████╔╝  ██║░░░░░███████╗░░░██║░░░╚█████╔╝██║░░██║
    ░╚═════╝░░╚════╝░  ╚═╝░░░░░╚══════╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝
   
    ░██████╗███████╗░█████╗░██████╗░███████╗████████ ░██████╗
    ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔════╝
    ╚█████╗░█████╗░░██║░░╚═╝██████╔╝█████╗░░░░░██║░░░╚█████╗░
    ░╚═══██╗██╔══╝░░██║░░██╗██╔══██╗██╔══╝░░░░░██║░░░░╚═══██╗
    ██████╔╝███████╗╚█████╔╝██║░░██║███████╗░░░██║░░░██████╔╝
    ╚═════╝░╚══════╝░╚════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═════╝░


    🔍 Go-Fetch-Secrets v1.0 - The Advanced Secret Scanner 🔍
    `
	color.New(color.FgCyan, color.Bold).Println(banner)
}

func loadPatterns(filename string) ([]Pattern, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading patterns file: %v", err)
	}

	var patternsMap PatternsJSON
	if err := json.Unmarshal(data, &patternsMap); err != nil {
		return nil, fmt.Errorf("error parsing patterns JSON: %v", err)
	}

	var patterns []Pattern
	for name, pattern := range patternsMap {
		patterns = append(patterns, Pattern{
			Name:    name,
			Pattern: pattern,
		})
	}

	return patterns, nil
}

func luhnCheck(number string) bool {
	var sum int
	var alternate bool

	numStr := strings.ReplaceAll(strings.ReplaceAll(number, " ", ""), "-", "")
	numRunes := []rune(numStr)

	for i := len(numRunes) - 1; i >= 0; i-- {
		n := int(numRunes[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n = (n % 10) + 1
			}
		}
		sum += n
		alternate = !alternate
	}

	return sum%10 == 0
}

func maskData(data string, visibleChars int) string {
	if len(data) <= visibleChars {
		return data
	}
	return strings.Repeat("*", len(data)-visibleChars) + data[len(data)-visibleChars:]
}

func (cfg *Config) processURL(url string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %v", url, err)
	}

	req.Header.Set("User-Agent", "Go-Fetch-Secrets/2.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("got status code %d for URL %s", resp.StatusCode, url)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response from %s: %v", url, err)
	}

	content := string(body)
	for _, pattern := range cfg.patterns {
		regex, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			continue
		}

		matches := regex.FindAllString(content, -1)
		for _, match := range matches {
			if _, exists := cfg.foundSecrets.LoadOrStore(match, true); exists {
				continue
			}

			result := Result{
				Type:     pattern.Name,
				Data:     match,
				URL:      url,
				TimeUsed: time.Since(start),
			}

			cfg.printResult(result)
		}
	}

	return nil
}

func (cfg *Config) printResult(result Result) {
	formatter := getFormatter(cfg.outputFormat)
	output := formatter.FormatResult(result)

	// Always print results to stdout, regardless of silent mode
	if cfg.outputFormat == "json" {
		// For JSON format, always print without color
		fmt.Println(output)
	} else {
		// For other formats, respect colorless setting
		if cfg.colorless {
			fmt.Println(output)
		} else {
			color.New(color.FgGreen).Println(output)
		}
	}

	// Write to output file if specified
	if cfg.outputFile != "" {
		f, err := os.OpenFile(cfg.outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			return
		}
		defer f.Close()

		// Write CSV header if it's a new CSV file
		if cfg.outputFormat == "csv" {
			fileInfo, err := f.Stat()
			if err == nil && fileInfo.Size() == 0 {
				fmt.Fprintln(f, "Type,Data,URL,Duration")
			}
		}

		fmt.Fprintln(f, output)
	}
}

func printStartupInfo(cfg *Config, patternCount int) {
	if !cfg.silent {
		printBanner()
		fmt.Printf("\nStarting scan with %d threads...\n", cfg.threads)
		fmt.Printf("Loaded %d patterns and %d URLs\n\n", patternCount, len(cfg.urls))
	}
}

func printError(err error, silent bool) {
	if err != nil {
		// Always print critical errors, even in silent mode
		if strings.Contains(err.Error(), "got status code") && silent {
			// Suppress HTTP status errors in silent mode
			return
		}
		fmt.Printf("Error: %v\n", err)
	}
}

func main() {
	urlFile := flag.String("list", "", "File containing list of URLs")
	threads := flag.Int64("threads", 10, "Number of concurrent threads")
	colorless := flag.Bool("colorless", false, "Disable colored output")
	outputFile := flag.String("output", "", "Output file to write results")
	format := flag.String("format", "txt", "Output format (txt, json, csv)")
	silent := flag.Bool("silent", false, "Suppress banner and status messages")
	helpFlag := flag.Bool("help", false, "Show help message")
	flag.Parse()

	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	cfg := &Config{
		threads:      *threads,
		colorless:    *colorless,
		outputFile:   *outputFile,
		outputFormat: *format,
		silent:       *silent,
		sem:          semaphore.NewWeighted(*threads),
		foundSecrets: sync.Map{},
	}

	if *urlFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Please provide a URL list file using --list flag\n")
		fmt.Fprintf(os.Stderr, "Use --help for usage information\n")
		os.Exit(1)
	}

	// Load patterns
	patterns, err := loadPatterns("patterns.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading patterns: %v\n", err)
		os.Exit(1)
	}
	cfg.patterns = patterns

	// Read URLs
	urls, err := readURLs(*urlFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading URLs: %v\n", err)
		os.Exit(1)
	}
	cfg.urls = urls

	// Only print banner and info if not silent
	if !cfg.silent {
		printBanner()
		fmt.Printf("\nStarting scan with %d threads...\n", cfg.threads)
		fmt.Printf("Loaded %d patterns and %d URLs\n\n", len(patterns), len(cfg.urls))
	}

	// Create error channel for handling errors
	errorChan := make(chan error, len(urls))

	// Process URLs
	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if err := cfg.processURL(url); err != nil {
				if !cfg.silent || !strings.Contains(err.Error(), "404") {
					errorChan <- err
				}
			}
		}(url)
	}

	go func() {
		wg.Wait()
		close(errorChan)
	}()

	for err := range errorChan {
		if !cfg.silent {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	}
}

func readURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening URL file: %v", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs found in the list")
	}

	return urls, nil
}

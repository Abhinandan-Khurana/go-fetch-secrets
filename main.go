package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/sync/semaphore"
)

const defaultPatternsURL = "https://raw.githubusercontent.com/Abhinandan-Khurana/go-fetch-secrets/refs/heads/main/patterns.json"

type Pattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

type PatternsJSON map[string]string

type Result struct {
	Type     string
	Data     string
	URL      string
	TimeUsed time.Duration
	Verified string
}

type Config struct {
	patterns     []Pattern
	urls         []string
	threads      int64
	colorless    bool
	silent       bool
	outputFile   string
	outputFormat string
	fingerprints string
	foundSecrets sync.Map
	sem          *semaphore.Weighted
}

type ResultFormatter interface {
	FormatResult(result Result) string
	FileExtension() string
}

type TextFormatter struct{}

func (f TextFormatter) FormatResult(result Result) string {
	return fmt.Sprintf("[+] Type: %s, Data: %s, URL: %s, Verified: %s (Found in: %s)",
		result.Type, result.Data, result.URL, result.Verified, result.TimeUsed)
}

func (f TextFormatter) FileExtension() string {
	return "txt"
}

type JSONOutput struct {
	Type     string        `json:"type"`
	Data     string        `json:"data"`
	URL      string        `json:"url"`
	Duration time.Duration `json:"duration(in ns)"`
	Verified string        `json:"verified"`
}

type JSONFormatter struct{}

func (f JSONFormatter) FormatResult(result Result) string {
	output := JSONOutput{
		Type:     result.Type,
		Data:     result.Data,
		URL:      result.URL,
		Duration: result.TimeUsed,
		Verified: result.Verified,
	}
	jsonData, _ := json.Marshal(output)
	return string(jsonData)
}

func (f JSONFormatter) FileExtension() string {
	return "json"
}

type CSVFormatter struct{}

func (f CSVFormatter) FormatResult(result Result) string {
	return fmt.Sprintf("%s,%s,%s,%s,%s",
		result.Type,
		result.Data,
		result.URL,
		result.Verified,
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
    --list         <file>    File containing list of URLs (required)
    --threads      <number>  Number of concurrent threads (default: 10)
    --colorless              Disable colored output
    --output       <file>    Output file to write results
    --format       <format>  Output format: txt, json, csv (default: txt)
    --fingerprints <file>    Custom fingerprints file (default: ~/.config/go-fetch-secrets/patterns.json)
    --silent                 Suppress banner and status messages
    --help                   Show this help message

Example:
    go run main.go --list urls.txt --threads 20 --format json --output results.json
    go run main.go --list urls.txt --silent --format csv --output results.csv --fingerprints custom_patterns.json

Note:
    If the fingerprints file is not found, it will be automatically downloaded.
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
    ╚═════╝░╚══════╝░╚════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚════╝░


    🔍 Go-Fetch-Secrets v1.2 - The Advanced Secret Scanner 🔍
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

			verified := verifySecret(pattern.Name, match)

			result := Result{
				Type:     pattern.Name,
				Data:     match,
				URL:      url,
				TimeUsed: time.Since(start),
				Verified: verified,
			}

			cfg.printResult(result)
		}
	}

	return nil
}

func (cfg *Config) printResult(result Result) {
	formatter := getFormatter(cfg.outputFormat)
	output := formatter.FormatResult(result)

	if cfg.outputFormat == "json" {
		fmt.Println(output)
	} else {
		if cfg.colorless {
			fmt.Println(output)
		} else {
			if result.Verified == "verified" {
				color.New(color.FgHiGreen, color.Bold).Println(output)
			} else {
				color.New(color.FgYellow).Println(output)
			}
		}
	}

	if cfg.outputFile != "" {
		f, err := os.OpenFile(cfg.outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			return
		}
		defer f.Close()

		if cfg.outputFormat == "csv" {
			fileInfo, err := f.Stat()
			if err == nil && fileInfo.Size() == 0 {
				fmt.Fprintln(f, "Type,Data,URL,Verified,Duration")
			}
		}

		fmt.Fprintln(f, output)
	}
}

func main() {
	urlFile := flag.String("list", "", "File containing list of URLs")
	threads := flag.Int64("threads", 10, "Number of concurrent threads")
	colorless := flag.Bool("colorless", false, "Disable colored output")
	outputFile := flag.String("output", "", "Output file to write results")
	format := flag.String("format", "txt", "Output format (txt, json, csv)")
	fingerprintsFile := flag.String("fingerprints", "", "Custom fingerprints file")
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
		fingerprints: *fingerprintsFile,
		silent:       *silent,
		sem:          semaphore.NewWeighted(*threads),
		foundSecrets: sync.Map{},
	}

	if *urlFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Please provide a URL list file using --list flag\n")
		fmt.Fprintf(os.Stderr, "Use --help for usage information\n")
		os.Exit(1)
	}

	fingerprintsPath, err := setupFingerprints(cfg.fingerprints, cfg.silent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up fingerprints: %v\n", err)
		os.Exit(1)
	}

	patterns, err := loadPatterns(fingerprintsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading patterns: %v\n", err)
		os.Exit(1)
	}
	cfg.patterns = patterns

	urls, err := readURLs(*urlFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading URLs: %v\n", err)
		os.Exit(1)
	}
	cfg.urls = urls

	if !cfg.silent {
		printBanner()
		fmt.Printf("\nStarting scan with %d threads...\n", cfg.threads)
		fmt.Printf("Loaded %d patterns from %s\n", len(patterns), fingerprintsPath)
		fmt.Printf("Scanning %d URLs\n\n", len(cfg.urls))
	}

	errorChan := make(chan error, len(urls))

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

func setupFingerprints(customPath string, silent bool) (string, error) {
	path := customPath
	if path == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not get user home directory: %v", err)
		}
		path = filepath.Join(homeDir, ".config", "go-fetch-secrets", "patterns.json")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if !silent {
			fmt.Printf("Fingerprints file not found at %s. Downloading from default URL...\n", path)
		}
		err := downloadFile(defaultPatternsURL, path)
		if err != nil {
			return "", fmt.Errorf("failed to download fingerprints file: %v", err)
		}
		if !silent {
			fmt.Println("Download complete.")
		}
	}
	return path, nil
}

func downloadFile(url, filepathStr string) error {
	dir := filepath.Dir(filepathStr)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("could not create directory %s: %v", dir, err)
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepathStr)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func verifySecret(secretType, secret string) string {
	var req *http.Request
	var err error

	// Standard client for most requests
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// The `secretType` is normalized to lowercase and without dashes/underscores for broad matching
	normalizedType := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(secretType, "-", ""), "_", ""))

	switch normalizedType {
	// Cloud & Infrastructure
	case "aws", "awstoken":
		// AWS verification is complex, requires signing requests with both key and secret.
		// A simple GET request is not sufficient to validate a key ID alone.
		return "unverified"
	case "gcp", "googleapikey", "googlecloudapikey", "googleoauthaccesstoken", "googlemapapikeys":
		// Test against multiple common Google APIs to cover different key types.
		urls := []string{
			"https://maps.googleapis.com/maps/api/geocode/json?address=1+main+st&key=" + secret,
			"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + secret,
			"https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=" + secret,
			// Static Maps
			"https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=" + secret,
			// Custom Search (CSE) — requires your CX (custom search engine id)
			"https://www.googleapis.com/customsearch/v1?q=restaurants+in+Austin&cx=CX_ID&key=" + secret,
			// Street View (image + metadata)
			"https://maps.googleapis.com/maps/api/streetview?size=600x300&location=46.414382%2C10.013988&key=" + secret,
			"https://maps.googleapis.com/maps/api/streetview/metadata?location=46.414382%2C10.013988&key=" + secret,
			// Directions
			"https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&mode=driving&key=" + secret,
			// Geocoding (forward + reverse)
			"https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway%2C+Mountain+View%2C+CA&key=" + secret,
			"https://maps.googleapis.com/maps/api/geocode/json?latlng=37.4219999%2C-122.0840575&key=" + secret,
			// Distance Matrix
			"https://maps.googleapis.com/maps/api/distancematrix/json?origins=40.6655101%2C-73.8918897&destinations=40.6905615%2C-73.9976592%7C40.659569%2C-73.933783&mode=driving&key=" + secret,
			// Places — Find Place From Text
			"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Google+Museum&inputtype=textquery&fields=place_id%2Cname%2Cgeometry&key=" + secret,
			// Places — Autocomplete (use a consistent SESSION_TOKEN per user session)
			"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=pizza&types=establishment&components=country%3Aus&sessiontoken=SESSION_TOKEN&key=" + secret,
			// Elevation
			"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536%2C-104.9847034&key=" + secret,
			// Time Zone
			"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810%2C-119.6822510&timestamp=1331161200&key=" + secret,
			// Roads — Nearest Roads
			"https://roads.googleapis.com/v1/nearestRoads?points=60.170880%2C24.942795%7C60.170879%2C24.942796&key=" + secret,
			// Geolocation (POST endpoint; URL still carries the key)
			"https://www.googleapis.com/geolocation/v1/geolocate?key=" + secret,
			// Roads — Snap to Roads (Route To Traveled)
			"https://roads.googleapis.com/v1/snapToRoads?path=60.170880%2C24.942795%7C60.170879%2C24.942796%7C60.170877%2C24.942797&interpolate=true&key=" + secret,
			// Roads — Speed Limits (by path)
			"https://roads.googleapis.com/v1/speedLimits?path=60.17088%2C24.942795%7C60.170879%2C24.942796&units=KPH&key=" + secret,
			// Roads — Speed Limits (by placeId)
			"https://roads.googleapis.com/v1/speedLimits?placeId=PLACE_ID&key=" + secret,
			// Places — Details
			"https://maps.googleapis.com/maps/api/place/details/json?place_id=PLACE_ID&fields=name%2Cformatted_address%2Cgeometry%2Copening_hours%2Cinternational_phone_number%2Cwebsite&key=" + secret,
			// Places — Nearby Search
			"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=47.6205%2C-122.3493&radius=1500&type=restaurant&key=" + secret,
			// Places — Text Search
			"https://maps.googleapis.com/maps/api/place/textsearch/json?query=coffee+in+seattle&key=" + secret,
			// Places — Photo (returns redirect to image)
			"https://maps.googleapis.com/maps/api/place/photo?maxwidth=800&photo_reference=PHOTO_REFERENCE&key=" + secret,
			// Places — Query Autocomplete
			"https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=pizza+near+new+york&key=" + secret,
		}
		for _, url := range urls {
			if resp, err := client.Get(url); err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					bodyBytes, _ := ioutil.ReadAll(resp.Body)
					// A valid key might still return an error message for a bad request, but an invalid key has a specific response.
					if !strings.Contains(string(bodyBytes), "error_message") && !strings.Contains(string(bodyBytes), "error") {
						return "verified"
					}
				}
			}
		}
		return "unverified"
	case "digitalocean":
		req, _ = http.NewRequest("GET", "https://api.digitalocean.com/v2/account", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "herokuapikey":
		req, _ = http.NewRequest("GET", "https://api.heroku.com/account", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	case "vercel":
		req, _ = http.NewRequest("GET", "https://api.vercel.com/v2/user", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "terraform", "pulumi":
		url := "https://app.terraform.io/api/v2/account/details"
		if normalizedType == "pulumi" {
			url = "https://api.pulumi.com/api/user"
		}
		req, _ = http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "token "+secret)

	// Code & CI/CD
	case "github", "githubtoken":
		req, _ = http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "gitlab":
		req, _ = http.NewRequest("GET", "https://gitlab.com/api/v4/user", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "bitbucket":
		req, _ = http.NewRequest("GET", "https://api.bitbucket.org/2.0/user", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "circleci":
		req, _ = http.NewRequest("GET", "https://circleci.com/api/v2/me", nil)
		req.Header.Set("Circle-Token", secret)
	case "buildkite":
		req, _ = http.NewRequest("GET", "https://api.buildkite.com/v2/user", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "jfrog", "artifactoryapitoken":
		// Requires Artifactory/Jfrog instance URL. Cannot be globally verified.
		return "unverified"
	case "snyk":
		req, _ = http.NewRequest("GET", "https://snyk.io/api/v1/user/me", nil)
		req.Header.Set("Authorization", "token "+secret)
	case "sonarcloud":
		req, _ = http.NewRequest("GET", "https://sonarcloud.io/api/users/search", nil)
		req.Header.Set("Authorization", "Bearer "+secret)

	// Messaging & Email
	case "slack", "slacktoken":
		req, _ = http.NewRequest("POST", "https://slack.com/api/auth.test", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "telegram":
		req, _ = http.NewRequest("GET", "https://api.telegram.org/bot"+secret+"/getMe", nil)
	case "twilio":
		// Requires Account SID, which is not part of the secret itself.
		return "unverified"
	case "mailgun", "mailgunapikey":
		req, _ = http.NewRequest("GET", "https://api.mailgun.net/v3/domains", nil)
		req.SetBasicAuth("api", secret)
	case "mailchimp", "mailchimpapikey":
		dc := "us1" // Default datacenter
		if parts := strings.Split(secret, "-"); len(parts) == 2 {
			dc = parts[1]
		}
		url := fmt.Sprintf("https://%s.api.mailchimp.com/3.0/ping", dc)
		req, _ = http.NewRequest("GET", url, nil)
		req.SetBasicAuth("anystring", secret)
	case "postmark":
		req, _ = http.NewRequest("GET", "https://api.postmarkapp.com/server", nil)
		req.Header.Set("X-Postmark-Server-Token", secret)
	case "sendgrid":
		req, _ = http.NewRequest("GET", "https://api.sendgrid.com/v3/user/profile", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "sendinblue":
		req, _ = http.NewRequest("GET", "https://api.sendinblue.com/v3/account", nil)
		req.Header.Set("api-key", secret)
	case "mailerlite":
		req, _ = http.NewRequest("GET", "https://api.mailerlite.com/api/v2/me", nil)
		req.Header.Set("X-MailerLite-ApiKey", secret)
	case "getresponse":
		req, _ = http.NewRequest("GET", "https://api.getresponse.com/v3/accounts", nil)
		req.Header.Set("X-Auth-Token", "api-key "+secret)

	// Payment & Finance
	case "stripe", "stripeapikey", "stripesecretkey":
		req, _ = http.NewRequest("GET", "https://api.stripe.com/v1/charges", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "squareaccesstoken", "squareoauthsecret":
		req, _ = http.NewRequest("GET", "https://connect.squareup.com/v2/locations", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "paypal", "paypalbraintreeaccesstoken":
		// Requires a separate token exchange, cannot verify a client secret directly.
		return "unverified"
	case "razorpay":
		// Requires both Key ID and Key Secret for a request.
		return "unverified"
	case "paystack":
		req, _ = http.NewRequest("GET", "https://api.paystack.co/balance", nil)
		req.Header.Set("Authorization", "Bearer "+secret)

	// Social & Productivity
	case "twitter", "twitterapikey", "twitterapisecret", "twitterbearertoken":
		req, _ = http.NewRequest("GET", "https://api.twitter.com/2/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "hubspot":
		req, _ = http.NewRequest("GET", "https://api.hubapi.com/crm/v3/objects/contacts?limit=1", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "notion":
		req, _ = http.NewRequest("GET", "https://api.notion.com/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Notion-Version", "2022-06-28")
	case "trello":
		// Trello API requires both an API key and a token for most requests.
		return "unverified"
	case "jira":
		// Requires Atlassian site URL (e.g., yourcompany.atlassian.net).
		return "unverified"
	case "zendesk":
		// Requires Zendesk subdomain.
		return "unverified"

	// Other Services
	case "openai":
		req, _ = http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "shodan":
		req, _ = http.NewRequest("GET", "https://api.shodan.io/account/profile?key="+secret, nil)
	case "doppler":
		req, _ = http.NewRequest("GET", "https://api.doppler.com/v3/configs", nil)
		req.SetBasicAuth(secret, "")
	case "sentry":
		req, _ = http.NewRequest("GET", "https://sentry.io/api/0/projects/", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "postman":
		req, _ = http.NewRequest("GET", "https://api.getpostman.com/me", nil)
		req.Header.Set("X-Api-Key", secret)
	case "npmtoken":
		req, _ = http.NewRequest("GET", "https://registry.npmjs.org/-/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "huggingface":
		req, _ = http.NewRequest("GET", "https://huggingface.co/api/whoami-v2", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
	case "weightsandbiases":
		req, _ = http.NewRequest("GET", "https://api.wandb.ai/v2/viewer", nil)
		req.SetBasicAuth("api", secret)
	case "okta":
		// Requires Okta domain URL.
		return "unverified"
	case "shopify":
		// Requires store URL (e.g., your-store.myshopify.com).
		return "unverified"

	default:
		return "unverified"
	}

	if err != nil || req == nil {
		return "unverified"
	}

	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	defer resp.Body.Close()

	// 2xx codes are a clear success.
	// 401/403 often mean the token is valid but lacks permissions, which still verifies its existence.
	if (resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.StatusCode == 401 || resp.StatusCode == 403 {
		return "verified"
	}

	return "unverified"
}

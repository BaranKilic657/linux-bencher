package main

import (
    "flag"
    "fmt"
    "os"
    "os/exec"
    "regexp"
    "sort"
    "strconv"
    "strings"

    "gopkg.in/yaml.v3"
)

// Colors (ANSI)
const (
    ColorReset  = "\033[0m"
    ColorRed    = "\033[31m"
    ColorGreen  = "\033[32m"
    ColorYellow = "\033[33m"
    ColorBlue   = "\033[34m"
    ColorGrey   = "\033[90m"
)

type Prerequisite struct {
    Type   string `yaml:"type"`
    Binary string `yaml:"binary,omitempty"`
    OnFail string `yaml:"on_fail,omitempty"`
}

type Expect struct {
    ExpectedSecurePatterns []string `yaml:"expected_secure_patterns,omitempty"`
    FailPatterns           []string `yaml:"fail_patterns,omitempty"`
    MustNotBeLoaded        bool     `yaml:"must_not_be_loaded,omitempty"`
    OnSecure               string   `yaml:"on_secure,omitempty"`
    OnInsecure             string   `yaml:"on_insecure,omitempty"`
}

type Step struct {
    Type    string `yaml:"type"`
    Command string `yaml:"command,omitempty"`
    Expect  Expect `yaml:"expect"`
}

type Check struct {
    ID            string         `yaml:"id"`
    Description   string         `yaml:"description"`
    Prerequisites []Prerequisite `yaml:"prerequisites"`
    Module        string         `yaml:"module,omitempty"`
    Steps         []Step         `yaml:"steps"`
    Remediation   string         `yaml:"remediation"`
    Scored        bool           `yaml:"scored"`
}

type CheckResult struct {
    ID          string
    Description string
    Status      string // PASS, FAIL, NA, INFO, ERROR
    Details     string
    Remediation string
}

func colorize(status, text string) string {
    switch status {
    case "PASS":
        return ColorGreen + text + ColorReset
    case "FAIL":
        return ColorRed + text + ColorReset
    case "NA":
        return ColorBlue + text + ColorReset
    case "INFO":
        return ColorYellow + text + ColorReset
    case "ERROR":
        return ColorGrey + text + ColorReset
    default:
        return text
    }
}

func binaryExists(bin string) bool {
    _, err := exec.LookPath(bin)
    return err == nil
}

func runShellCommand(cmdStr string) (string, error) {
    parts := strings.Fields(cmdStr)
    if len(parts) == 0 {
        return "", fmt.Errorf("empty command")
    }
    cmd := exec.Command(parts[0], parts[1:]...)
    out, err := cmd.CombinedOutput()
    return string(out), err
}

// Run one check, return PASS/FAIL/NA/INFO/ERROR
func evaluateCheck(check Check) CheckResult {
    // Prerequisite check
    for _, pre := range check.Prerequisites {
        if pre.Type == "binary_exists" {
            if !binaryExists(pre.Binary) {
                return CheckResult{
                    ID:          check.ID,
                    Description: check.Description,
                    Status:      strings.ToUpper(pre.OnFail),
                    Details:     fmt.Sprintf("Binary '%s' not found", pre.Binary),
                    Remediation: check.Remediation,
                }
            }
        }
    }

    // Steps
    for _, step := range check.Steps {
        if step.Type == "shell" {
            output, err := runShellCommand(step.Command)
            output = strings.TrimSpace(output)

            // 1. Secure patterns (PASS if ANY matches)
            for _, pat := range step.Expect.ExpectedSecurePatterns {
                re := regexp.MustCompile(pat)
                if re.MatchString(output) {
                    return CheckResult{
                        ID:          check.ID,
                        Description: check.Description,
                        Status:      strings.ToUpper(step.Expect.OnSecure),
                        Details:     fmt.Sprintf("Matched secure pattern: %q\nOutput: %q", pat, output),
                        Remediation: "",
                    }
                }
            }

            // 2. must_not_be_loaded: fail if found in lsmod output
            if step.Expect.MustNotBeLoaded && len(step.Expect.FailPatterns) > 0 {
                for _, pat := range step.Expect.FailPatterns {
                    re := regexp.MustCompile(pat)
                    if re.MatchString(output) {
                        return CheckResult{
                            ID:          check.ID,
                            Description: check.Description,
                            Status:      strings.ToUpper(step.Expect.OnInsecure),
                            Details:     fmt.Sprintf("Module loaded: matched pattern: %q\nOutput: %q", pat, output),
                            Remediation: check.Remediation,
                        }
                    }
                }
                // If not found: PASS
                return CheckResult{
                    ID:          check.ID,
                    Description: check.Description,
                    Status:      strings.ToUpper(step.Expect.OnSecure),
                    Details:     fmt.Sprintf("Module not loaded (lsmod): %q", output),
                    Remediation: "",
                }
            }

            // 3. Insecure (FAIL if ANY fail_pattern matches)
            for _, pat := range step.Expect.FailPatterns {
                re := regexp.MustCompile(pat)
                if re.MatchString(output) {
                    return CheckResult{
                        ID:          check.ID,
                        Description: check.Description,
                        Status:      strings.ToUpper(step.Expect.OnInsecure),
                        Details:     fmt.Sprintf("Matched fail pattern: %q\nOutput: %q", pat, output),
                        Remediation: check.Remediation,
                    }
                }
            }

            // 4. Unknown state (INFO)
            if err != nil {
                return CheckResult{
                    ID:          check.ID,
                    Description: check.Description,
                    Status:      "ERROR",
                    Details:     fmt.Sprintf("Shell error: %v\nOutput: %q", err, output),
                    Remediation: check.Remediation,
                }
            }
        }
    }
    // All steps pass, or module not loaded (PASS)
    return CheckResult{
        ID:          check.ID,
        Description: check.Description,
        Status:      "PASS",
        Details:     "All checks passed",
        Remediation: check.Remediation,
    }
}

// Range and filter logic

func parseRange(r string) (string, string) {
    parts := strings.Split(r, "-")
    if len(parts) != 2 {
        return "", ""
    }
    return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func idToSlice(id string) []int {
    parts := strings.Split(id, ".")
    res := []int{}
    for _, p := range parts {
        n, err := strconv.Atoi(p)
        if err != nil {
            break
        }
        res = append(res, n)
    }
    return res
}

func idInRange(id, start, end string) bool {
    idS := idToSlice(id)
    sS := idToSlice(start)
    eS := idToSlice(end)
    for i := 0; i < len(sS) && i < len(idS) && i < len(eS); i++ {
        if idS[i] < sS[i] {
            return false
        }
        if idS[i] > eS[i] {
            return false
        }
    }
    return true
}

// Command-line filter: --id 1.1.1, --range 1.1.1.1-1.1.1.5, --step 2
func filterChecks(checks []Check, idFilter string, rangeFilter string, step int) []Check {
    var filtered []Check
    start, end := "", ""
    if rangeFilter != "" {
        start, end = parseRange(rangeFilter)
    }
    for idx, c := range checks {
        // Step filtering
        if step > 1 && idx%step != 0 {
            continue
        }
        // Range filtering
        if start != "" && end != "" && !idInRange(c.ID, start, end) {
            continue
        }
        // ID filtering
        if idFilter != "" && !strings.HasPrefix(c.ID, idFilter) {
            continue
        }
        filtered = append(filtered, c)
    }
    return filtered
}

func main() {
    // CLI
    yamlFile := flag.String("file", "checks.yaml", "YAML file with checks")
    idFilter := flag.String("id", "", "Filter checks by top-level ID (e.g. 1.1.1)")
    rangeFilter := flag.String("range", "", "Filter checks by ID range (e.g. 1.1.1.1-1.1.1.5)")
    step := flag.Int("step", 0, "Run every Nth check only (e.g. --step 2)")
    flag.Parse()

    data, err := os.ReadFile(*yamlFile)
    if err != nil {
        fmt.Println(ColorRed + "Could not read YAML file: " + err.Error() + ColorReset)
        os.Exit(1)
    }
    var checks []Check
    if err := yaml.Unmarshal(data, &checks); err != nil {
        fmt.Println(ColorRed + "YAML parsing error: " + err.Error() + ColorReset)
        os.Exit(1)
    }

    checks = filterChecks(checks, *idFilter, *rangeFilter, *step)

    // Run and collect results
    var results []CheckResult
    statusCount := map[string]int{}
    groupStatus := map[string]string{}
    groupChecks := map[string][]string{}

    fmt.Println(ColorBlue + "=== Check Results ===" + ColorReset)
    for _, check := range checks {
        result := evaluateCheck(check)
        results = append(results, result)
        statusCount[result.Status]++

        // Print details
        fmt.Printf("[%s] %s: %s\n", check.ID, check.Description, colorize(result.Status, result.Status))
        if result.Status != "PASS" {
            fmt.Printf("  Details: %s\n", result.Details)
            if result.Remediation != "" {
                fmt.Printf("  Remediation: %s\n", result.Remediation)
            }
        }

        // For summary
        topID := strings.Join(strings.Split(check.ID, ".")[:3], ".") // 1.1.1 style
        groupChecks[topID] = append(groupChecks[topID], fmt.Sprintf("%s (%s)", check.ID, result.Status))
        if result.Status == "FAIL" && groupStatus[topID] != "FAIL" {
            groupStatus[topID] = "FAIL"
        } else if result.Status == "PASS" && groupStatus[topID] == "" {
            groupStatus[topID] = "PASS"
        }
    }

    // Summary
    fmt.Println(ColorBlue + "\n=== Summary by Group (e.g., 1.1.1) ===" + ColorReset)
    keys := make([]string, 0, len(groupStatus))
    for k := range groupStatus {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    for _, k := range keys {
        fmt.Printf("%s: %s\n", k, colorize(groupStatus[k], groupStatus[k]))
        fmt.Printf("   Sub-checks: %s\n", strings.Join(groupChecks[k], ", "))
    }
    fmt.Println(ColorBlue + "\n=== Totals ===" + ColorReset)
    fmt.Printf("PASS: %d  FAIL: %d  NA: %d  INFO: %d  ERROR: %d  (Total: %d)\n",
        statusCount["PASS"], statusCount["FAIL"], statusCount["NA"], statusCount["INFO"], statusCount["ERROR"], len(results))

    fmt.Println(ColorGrey + "\nUse --id, --range, --step for filtering. Example: ./checker -file checks.yaml --range 1.1.1.1-1.1.1.5 --step 2" + ColorReset)
}

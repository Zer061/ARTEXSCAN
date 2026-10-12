// artexscan - quet port 80/443/8787 theo danh sach IP va fingerprint ung dung ARTEX.
//
// Thiet ke cho quy mo tren 50.000 IP: moi IP la mot don vi cong viec, worker pool
// co gioi han, co rate-limit tho, ghi ket qua tang dan va ho tro resume.
//
// Build:   go build -o artexscan .
// Profile: ./artexscan -profile http://host:8787/login
// Scan:    ./artexscan -targets ips.txt -rules artex-rules.json -out ./ket-qua
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------- cau hinh

type options struct {
	targetsFile string
	rulesFile   string
	outDir      string
	ports       string
	concurrency int
	rate        int
	dialTimeout time.Duration
	httpTimeout time.Duration
	userAgent   string
	maxBody     int64
	allowLarge  bool
	resume      bool
	noShuffle   bool
	verbose     bool
	profileURL  string
}

// ---------------------------------------------------------------- signature

type rule struct {
	ID    string `json:"id"`
	Field string `json:"field"` // title | body | server | powered_by | location | status |
	// cookie | cert_cn | cert_san | favicon_mmh3 | favicon_sha256 |
	// url | header:<ten-header>
	Match         string `json:"match"` // contains | equals | prefix | regex
	Value         string `json:"value"`
	Score         int    `json:"score"`
	CaseSensitive bool   `json:"case_sensitive"`

	re *regexp.Regexp
}

type ruleSet struct {
	Name        string   `json:"name"`
	Paths       []string `json:"paths"`
	MinScore    int      `json:"min_score"`
	SuspectFrom int      `json:"suspect_from"`
	Rules       []*rule  `json:"rules"`
}

func loadRules(path string) (*ruleSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs ruleSet
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, fmt.Errorf("rules JSON khong hop le: %w", err)
	}
	if len(rs.Paths) == 0 {
		rs.Paths = []string{"/"}
	}
	if rs.MinScore <= 0 {
		rs.MinScore = 3
	}
	if rs.SuspectFrom <= 0 {
		rs.SuspectFrom = 1
	}
	if len(rs.Rules) == 0 {
		return nil, fmt.Errorf("rules rong - khong co dau hieu nao de doi chieu")
	}
	for i, r := range rs.Rules {
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%d", i+1)
		}
		if r.Score == 0 {
			r.Score = 1
		}
		if r.Match == "" {
			r.Match = "contains"
		}
		if r.Match == "regex" {
			expr := r.Value
			if !r.CaseSensitive {
				expr = "(?i)" + expr
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("rule %s: regex loi: %w", r.ID, err)
			}
			r.re = re
		}
	}
	return &rs, nil
}

// ---------------------------------------------------------------- ket qua

type probeResult struct {
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Scheme      string   `json:"scheme"`
	Path        string   `json:"path"`
	Status      int      `json:"status"`
	Title       string   `json:"title"`
	Server      string   `json:"server"`
	PoweredBy   string   `json:"powered_by"`
	Location    string   `json:"location"`
	Cookies     []string `json:"cookies"`
	FaviconMMH3 string   `json:"favicon_mmh3"`
	FaviconSHA  string   `json:"favicon_sha256"`
	CertCN      string   `json:"cert_cn"`
	CertSAN     []string `json:"cert_san"`
	BodyLen     int      `json:"body_len"`
	Score       int      `json:"score"`
	Matched     []string `json:"matched"`
	Verdict     string   `json:"verdict"` // artex | suspect | other
	Error       string   `json:"error,omitempty"`

	headers map[string]string
	body    string
}

func (p *probeResult) hostPort() string {
	return net.JoinHostPort(p.IP, strconv.Itoa(p.Port))
}

// ---------------------------------------------------------------- doi chieu

func fieldValues(p *probeResult, field string) []string {
	f := strings.ToLower(strings.TrimSpace(field))
	switch {
	case f == "title":
		return []string{p.Title}
	case f == "body":
		return []string{p.body}
	case f == "server":
		return []string{p.Server}
	case f == "powered_by":
		return []string{p.PoweredBy}
	case f == "location":
		return []string{p.Location}
	case f == "status":
		return []string{strconv.Itoa(p.Status)}
	case f == "cookie":
		return p.Cookies
	case f == "cert_cn":
		return []string{p.CertCN}
	case f == "cert_san":
		return p.CertSAN
	case f == "favicon_mmh3":
		return []string{p.FaviconMMH3}
	case f == "favicon_sha256":
		return []string{p.FaviconSHA}
	case f == "url":
		return []string{fmt.Sprintf("%s://%s%s", p.Scheme, p.hostPort(), p.Path)}
	case strings.HasPrefix(f, "header:"):
		name := strings.TrimSpace(strings.TrimPrefix(f, "header:"))
		if v, ok := p.headers[strings.ToLower(name)]; ok {
			return []string{v}
		}
		return nil
	}
	return nil
}

func (r *rule) matches(p *probeResult) bool {
	vals := fieldValues(p, r.Field)
	if len(vals) == 0 {
		return false
	}
	want := r.Value
	for _, got := range vals {
		if got == "" {
			continue
		}
		g, w := got, want
		if !r.CaseSensitive && r.Match != "regex" {
			g = strings.ToLower(g)
			w = strings.ToLower(w)
		}
		switch r.Match {
		case "equals":
			if g == w {
				return true
			}
		case "prefix":
			if strings.HasPrefix(g, w) {
				return true
			}
		case "regex":
			if r.re != nil && r.re.MatchString(got) {
				return true
			}
		default: // contains
			if strings.Contains(g, w) {
				return true
			}
		}
	}
	return false
}

func (rs *ruleSet) evaluate(p *probeResult) {
	p.Score = 0
	p.Matched = p.Matched[:0]
	for _, r := range rs.Rules {
		if r.matches(p) {
			p.Score += r.Score
			p.Matched = append(p.Matched, fmt.Sprintf("%s(+%d)", r.ID, r.Score))
		}
	}
	switch {
	case p.Score >= rs.MinScore:
		p.Verdict = "artex"
	case p.Score >= rs.SuspectFrom:
		p.Verdict = "suspect"
	default:
		p.Verdict = "other"
	}
}

// ---------------------------------------------------------------- favicon

// mmh3_32 - MurmurHash3 x86 32-bit, tra ve int32 co dau de trung voi
// mmh3.hash() cua Python (chuan ma Shodan dung cho http.favicon.hash).
func mmh3_32(data []byte, seed uint32) int32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593

	h1 := seed
	nblocks := len(data) / 4

	for i := 0; i < nblocks; i++ {
		j := i * 4
		k1 := uint32(data[j]) | uint32(data[j+1])<<8 | uint32(data[j+2])<<16 | uint32(data[j+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}

// b64Wrapped mo phong base64.encodebytes() cua Python: xuong dong moi 76 ky tu,
// ke ca o dong cuoi. Phai giong het thi hash moi khop voi Shodan/FOFA.
func b64Wrapped(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var sb strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		sb.WriteString(enc[i:end])
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

func faviconHashes(body []byte) (string, string) {
	if len(body) == 0 {
		return "", ""
	}
	h := mmh3_32(b64Wrapped(body), 0)
	sum := sha256.Sum256(body)
	return strconv.Itoa(int(h)), hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- HTTP

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var wsRe = regexp.MustCompile(`\s+`)

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := wsRe.ReplaceAllString(m[1], " ")
	return strings.TrimSpace(t)
}

func newClient(o *options) *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   o.dialTimeout,
			KeepAlive: -1,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // can doc duoc cert tu ky de fingerprint
			MinVersion:         tls.VersionTLS10,
		},
		TLSHandshakeTimeout:   o.dialTimeout,
		ResponseHeaderTimeout: o.httpTimeout,
		DisableKeepAlives:     true,
		DisableCompression:    false,
		MaxIdleConns:          0,
		ForceAttemptHTTP2:     false,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // khong tu dong theo redirect
		},
	}
}

func schemesFor(port int) []string {
	switch port {
	case 443, 8443, 9443:
		return []string{"https", "http"}
	case 80, 8080:
		return []string{"http", "https"}
	default:
		return []string{"http", "https"}
	}
}

// fetch lay mot URL va do day cac truong fingerprint vao probeResult.
func fetch(ctx context.Context, cl *http.Client, o *options, scheme, hostPort, path string) (*probeResult, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	u := fmt.Sprintf("%s://%s%s", scheme, hostPort, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", o.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, o.maxBody))

	p := &probeResult{
		IP:      host,
		Port:    port,
		Scheme:  scheme,
		Path:    path,
		Status:  resp.StatusCode,
		BodyLen: len(bodyBytes),
		headers: make(map[string]string, len(resp.Header)),
		body:    string(bodyBytes),
	}
	for k, v := range resp.Header {
		if len(v) > 0 {
			p.headers[strings.ToLower(k)] = v[0]
		}
	}
	p.Title = extractTitle(p.body)
	p.Server = p.headers["server"]
	p.PoweredBy = p.headers["x-powered-by"]
	p.Location = p.headers["location"]
	for _, c := range resp.Cookies() {
		p.Cookies = append(p.Cookies, c.Name)
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		p.CertCN = cert.Subject.CommonName
		p.CertSAN = append(p.CertSAN, cert.DNSNames...)
	}
	return p, nil
}

func fetchFavicon(ctx context.Context, cl *http.Client, o *options, scheme, hostPort string) (string, string) {
	u := fmt.Sprintf("%s://%s/favicon.ico", scheme, hostPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", o.userAgent)
	req.Header.Set("Connection", "close")
	resp, err := cl.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return faviconHashes(b)
}

// ---------------------------------------------------------------- muc tieu

func ipToU32(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

func u32ToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// parseTargets doc file muc tieu. Moi dong chap nhan:
//
//	10.0.0.5                 IP don
//	10.0.0.0/24              CIDR
//	10.0.0.1-10.0.0.50       dai IP
//	10.0.0.5,ten-may,don-vi  CSV - lay cot dau tien
//	# ghi chu                bo qua
func parseTargets(path string, allowLarge bool) ([]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var out []string
	var warns []string

	add := func(ip string) {
		if _, ok := seen[ip]; ok {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Cat ghi chu cuoi dong
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Cat cac cot phu cua CSV/TSV
		if i := strings.IndexAny(line, ",;\t"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// "10.0.0.1 - 10.0.0.9" la mot dai, khong phai IP + ten may
		if strings.Contains(line, "-") {
			line = strings.ReplaceAll(line, " ", "")
		} else if i := strings.IndexByte(line, ' '); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		switch {
		case strings.Contains(line, "/"):
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil || ipnet.IP.To4() == nil {
				warns = append(warns, fmt.Sprintf("dong %d: bo qua CIDR khong hop le %q", lineNo, line))
				continue
			}
			ones, bits := ipnet.Mask.Size()
			count := uint64(1) << uint(bits-ones)
			if count > 1<<22 {
				warns = append(warns, fmt.Sprintf("dong %d: %s co %d dia chi - vuot tran an toan 4.194.304, bo qua", lineNo, line, count))
				continue
			}
			if count > 65536 && !allowLarge {
				warns = append(warns, fmt.Sprintf("dong %d: %s co %d dia chi - bo qua, them -allow-large neu that su can", lineNo, line, count))
				continue
			}
			base, ok := ipToU32(ipnet.IP.String())
			if !ok {
				continue
			}
			for i := uint64(0); i < count; i++ {
				add(u32ToIP(base + uint32(i)))
			}

		case strings.Contains(line, "-"):
			parts := strings.SplitN(line, "-", 2)
			lo, ok1 := ipToU32(parts[0])
			hi, ok2 := ipToU32(parts[1])
			if !ok1 || !ok2 || hi < lo {
				warns = append(warns, fmt.Sprintf("dong %d: bo qua dai IP khong hop le %q", lineNo, line))
				continue
			}
			if uint64(hi-lo) > 65536 && !allowLarge {
				warns = append(warns, fmt.Sprintf("dong %d: dai %s qua lon - bo qua, them -allow-large neu that su can", lineNo, line))
				continue
			}
			for v := lo; ; v++ {
				add(u32ToIP(v))
				if v == hi {
					break
				}
			}

		default:
			if _, ok := ipToU32(line); !ok {
				warns = append(warns, fmt.Sprintf("dong %d: bo qua %q (khong phai IPv4)", lineNo, line))
				continue
			}
			add(line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, warns, err
	}
	return out, warns, nil
}

func parsePorts(s string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("port khong hop le: %q", part)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("khong co port nao")
	}
	return ports, nil
}

// ---------------------------------------------------------------- rate limit

type limiter struct{ ch chan struct{} }

func newLimiter(rps int) *limiter {
	if rps <= 0 {
		return &limiter{}
	}
	l := &limiter{ch: make(chan struct{}, rps)}
	go func() {
		interval := time.Second / time.Duration(rps)
		if interval < time.Microsecond {
			interval = time.Microsecond
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			select {
			case l.ch <- struct{}{}:
			default:
			}
		}
	}()
	return l
}

func (l *limiter) wait() {
	if l.ch != nil {
		<-l.ch
	}
}

// ---------------------------------------------------------------- ghi ket qua

type writers struct {
	mu      sync.Mutex
	hitsF   *os.File
	hits    *bufio.Writer
	jsonF   *os.File
	jsonl   *bufio.Writer
	csvF    *os.File
	csvW    *csv.Writer
	stateF  *os.File
	state   *bufio.Writer
	hitList []string
}

func newWriters(dir string, resume bool) (*writers, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	mode := os.O_CREATE | os.O_WRONLY
	if resume {
		mode |= os.O_APPEND
	} else {
		mode |= os.O_TRUNC
	}

	w := &writers{}
	var err error
	if w.hitsF, err = os.OpenFile(dir+"/artex.txt", mode, 0o644); err != nil {
		return nil, err
	}
	if w.jsonF, err = os.OpenFile(dir+"/results.jsonl", mode, 0o644); err != nil {
		return nil, err
	}
	newCSV := true
	if resume {
		if st, serr := os.Stat(dir + "/results.csv"); serr == nil && st.Size() > 0 {
			newCSV = false
		}
	}
	if w.csvF, err = os.OpenFile(dir+"/results.csv", mode, 0o644); err != nil {
		return nil, err
	}
	stateMode := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !resume {
		stateMode = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	if w.stateF, err = os.OpenFile(dir+"/.scanned", stateMode, 0o644); err != nil {
		return nil, err
	}
	if resume {
		// Giu lai ket qua cua cac lan chay truoc, neu khong artex.txt se bi ghi de.
		w.hitList = readLines(dir + "/artex.txt")
	}

	w.hits = bufio.NewWriter(w.hitsF)
	w.jsonl = bufio.NewWriter(w.jsonF)
	w.csvW = csv.NewWriter(w.csvF)
	w.state = bufio.NewWriter(w.stateF)

	if newCSV {
		_ = w.csvW.Write([]string{
			"ip", "port", "scheme", "path", "status", "verdict", "score",
			"title", "server", "powered_by", "location", "cert_cn",
			"favicon_mmh3", "body_len", "matched",
		})
		w.csvW.Flush()
	}
	return w, nil
}

func (w *writers) record(p *probeResult) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if p.Verdict == "artex" {
		line := p.hostPort()
		w.hitList = append(w.hitList, line)
		fmt.Fprintln(w.hits, line)
		w.hits.Flush()
		w.hitsF.Sync()
	}

	if b, err := json.Marshal(p); err == nil {
		w.jsonl.Write(b)
		w.jsonl.WriteByte('\n')
	}
	_ = w.csvW.Write([]string{
		p.IP, strconv.Itoa(p.Port), p.Scheme, p.Path, strconv.Itoa(p.Status),
		p.Verdict, strconv.Itoa(p.Score), p.Title, p.Server, p.PoweredBy,
		p.Location, p.CertCN, p.FaviconMMH3, strconv.Itoa(p.BodyLen),
		strings.Join(p.Matched, "|"),
	})
}

func (w *writers) markDone(ip string) {
	w.mu.Lock()
	fmt.Fprintln(w.state, ip)
	w.mu.Unlock()
}

func (w *writers) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.hits.Flush()
	w.jsonl.Flush()
	w.csvW.Flush()
	w.state.Flush()
}

func (w *writers) close() {
	w.flush()
	w.hitsF.Close()
	w.jsonF.Close()
	w.csvF.Close()
	w.stateF.Close()
}

// rewriteSorted ghi lai artex.txt da sap xep theo IP roi port.
func (w *writers) rewriteSorted(dir string) error {
	w.mu.Lock()
	list := append([]string(nil), w.hitList...)
	w.mu.Unlock()

	uniq := make(map[string]struct{}, len(list))
	var clean []string
	for _, s := range list {
		if _, ok := uniq[s]; ok {
			continue
		}
		uniq[s] = struct{}{}
		clean = append(clean, s)
	}
	sort.Slice(clean, func(i, j int) bool {
		hi, pi, _ := net.SplitHostPort(clean[i])
		hj, pj, _ := net.SplitHostPort(clean[j])
		ui, _ := ipToU32(hi)
		uj, _ := ipToU32(hj)
		if ui != uj {
			return ui < uj
		}
		ni, _ := strconv.Atoi(pi)
		nj, _ := strconv.Atoi(pj)
		return ni < nj
	})
	var out []byte
	if len(clean) > 0 {
		out = []byte(strings.Join(clean, "\n") + "\n")
	}
	return os.WriteFile(dir+"/artex.txt", out, 0o644)
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func loadScanned(dir string) map[string]struct{} {
	done := make(map[string]struct{})
	for _, s := range readLines(dir + "/.scanned") {
		done[s] = struct{}{}
	}
	return done
}

// ---------------------------------------------------------------- quet

type counters struct {
	ipsDone  int64
	openPort int64
	httpOK   int64
	hits     int64
	suspect  int64
}

func scanIP(ctx context.Context, ip string, ports []int, o *options, rs *ruleSet, cl *http.Client, lim *limiter, w *writers, c *counters) {
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		lim.wait()
		hostPort := net.JoinHostPort(ip, strconv.Itoa(port))

		d := net.Dialer{Timeout: o.dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", hostPort)
		if err != nil {
			continue
		}
		conn.Close()
		atomic.AddInt64(&c.openPort, 1)

		// Port mo -> thu fingerprint HTTP/HTTPS
		var best *probeResult
		var fMMH3, fSHA string
		faviconDone := false

		for _, scheme := range schemesFor(port) {
			reachable := false
			for _, path := range rs.Paths {
				rctx, cancel := context.WithTimeout(ctx, o.httpTimeout+o.dialTimeout)
				p, err := fetch(rctx, cl, o, scheme, hostPort, path)
				cancel()
				if err != nil {
					continue
				}
				reachable = true

				if !faviconDone {
					fctx, fcancel := context.WithTimeout(ctx, o.httpTimeout)
					fMMH3, fSHA = fetchFavicon(fctx, cl, o, scheme, hostPort)
					fcancel()
					faviconDone = true
				}
				p.FaviconMMH3, p.FaviconSHA = fMMH3, fSHA

				rs.evaluate(p)
				if best == nil || p.Score > best.Score {
					best = p
				}
				if best.Verdict == "artex" {
					break
				}
			}
			if reachable {
				break // scheme nay dung roi, khong thu scheme con lai
			}
		}

		if best == nil {
			// Port mo nhung khong noi chuyen duoc HTTP(S)
			best = &probeResult{IP: ip, Port: port, Verdict: "other", Error: "port mo nhung khong phai HTTP(S)"}
		} else {
			atomic.AddInt64(&c.httpOK, 1)
		}

		switch best.Verdict {
		case "artex":
			atomic.AddInt64(&c.hits, 1)
			if o.verbose {
				fmt.Printf("[ARTEX]   %s  score=%d  %q  %s\n", best.hostPort(), best.Score, best.Title, strings.Join(best.Matched, ","))
			}
		case "suspect":
			atomic.AddInt64(&c.suspect, 1)
			if o.verbose {
				fmt.Printf("[nghi ngo] %s  score=%d  %q\n", best.hostPort(), best.Score, best.Title)
			}
		}
		w.record(best)
	}
	atomic.AddInt64(&c.ipsDone, 1)
	w.markDone(ip)
}

// ---------------------------------------------------------------- profile

func runProfile(o *options) error {
	u, err := url.Parse(o.profileURL)
	if err != nil {
		return fmt.Errorf("URL khong hop le: %w", err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("URL phai co http:// hoac https://")
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	cl := newClient(o)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p, err := fetch(ctx, cl, o, u.Scheme, host, path)
	if err != nil {
		return fmt.Errorf("khong truy cap duoc %s: %w", o.profileURL, err)
	}
	p.FaviconMMH3, p.FaviconSHA = fetchFavicon(ctx, cl, o, u.Scheme, host)

	fmt.Println("=========== DAU HIEU QUAN SAT DUOC ===========")
	fmt.Printf("URL            : %s\n", o.profileURL)
	fmt.Printf("HTTP status    : %d\n", p.Status)
	fmt.Printf("Title          : %q\n", p.Title)
	fmt.Printf("Server         : %q\n", p.Server)
	fmt.Printf("X-Powered-By   : %q\n", p.PoweredBy)
	fmt.Printf("Location       : %q\n", p.Location)
	fmt.Printf("Cookie names   : %v\n", p.Cookies)
	fmt.Printf("Cert CN        : %q\n", p.CertCN)
	fmt.Printf("Cert SAN       : %v\n", p.CertSAN)
	fmt.Printf("Favicon mmh3   : %s\n", p.FaviconMMH3)
	fmt.Printf("Favicon sha256 : %s\n", p.FaviconSHA)
	fmt.Printf("Body length    : %d\n", p.BodyLen)

	fmt.Println("\n----------- TAT CA RESPONSE HEADER -----------")
	keys := make([]string, 0, len(p.headers))
	for k := range p.headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%-28s %s\n", k+":", p.headers[k])
	}

	fmt.Println("\n----------- CHUOI DANG CHU Y TRONG BODY -----------")
	for _, s := range interestingStrings(p.body) {
		fmt.Println("  " + s)
	}

	fmt.Println("\n=========== GOI Y FILE RULES (soat lai truoc khi dung) ===========")
	suggested := suggestRules(p)
	b, _ := json.MarshalIndent(suggested, "", "  ")
	fmt.Println(string(b))
	fmt.Println("\n# Luu y: hay bo cac rule qua chung chung (vi du Server: nginx)")
	fmt.Println("# vi chung se khop voi hang nghin host khong phai ARTEX.")
	return nil
}

var assetRe = regexp.MustCompile(`(?i)(?:src|href)=["']([^"']+\.(?:js|css))["']`)
var appNameRe = regexp.MustCompile(`(?i)\bartex[a-z0-9_\-]*`)

func interestingStrings(body string) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, m := range appNameRe.FindAllString(body, 40) {
		add(`chuoi "artex": ` + m)
	}
	for _, m := range assetRe.FindAllStringSubmatch(body, 40) {
		add("asset: " + m[1])
	}
	if strings.Contains(body, "__NEXT_DATA__") {
		add("framework: Next.js (__NEXT_DATA__)")
	}
	if strings.Contains(body, "id=\"root\"") || strings.Contains(body, "id='root'") {
		add("framework: React (div#root)")
	}
	if strings.Contains(body, "id=\"app\"") {
		add("framework: Vue/Nuxt (div#app)")
	}
	if strings.Contains(body, "ng-version") {
		add("framework: Angular (ng-version)")
	}
	if len(out) == 0 {
		add("(khong thay dau hieu noi bat - xem lai body thu cong)")
	}
	return out
}

func suggestRules(p *probeResult) *ruleSet {
	rs := &ruleSet{
		Name:        "ARTEX",
		Paths:       []string{"/", "/login"},
		MinScore:    3,
		SuspectFrom: 2,
	}
	if p.Title != "" {
		rs.Rules = append(rs.Rules, &rule{
			ID: "title", Field: "title", Match: "contains", Value: p.Title, Score: 3,
		})
	}
	if p.FaviconMMH3 != "" {
		rs.Rules = append(rs.Rules, &rule{
			ID: "favicon", Field: "favicon_mmh3", Match: "equals", Value: p.FaviconMMH3, Score: 4,
		})
	}
	for _, m := range appNameRe.FindAllString(p.body, 3) {
		rs.Rules = append(rs.Rules, &rule{
			ID: "body-" + strings.ToLower(m), Field: "body", Match: "contains", Value: m, Score: 3,
		})
		break
	}
	for _, m := range assetRe.FindAllStringSubmatch(p.body, 3) {
		rs.Rules = append(rs.Rules, &rule{
			ID: "asset", Field: "body", Match: "contains", Value: m[1], Score: 2,
		})
		break
	}
	for _, c := range p.Cookies {
		rs.Rules = append(rs.Rules, &rule{
			ID: "cookie-" + strings.ToLower(c), Field: "cookie", Match: "equals", Value: c, Score: 2,
		})
	}
	if p.CertCN != "" {
		rs.Rules = append(rs.Rules, &rule{
			ID: "cert-cn", Field: "cert_cn", Match: "contains", Value: p.CertCN, Score: 2,
		})
	}
	if len(rs.Rules) == 0 {
		rs.Rules = append(rs.Rules, &rule{
			ID: "dat-tay", Field: "body", Match: "contains", Value: "DOI_CHUOI_NAY", Score: 3,
		})
	}
	return rs
}

// ---------------------------------------------------------------- main

func main() {
	o := &options{}
	flag.StringVar(&o.targetsFile, "targets", "", "file danh sach IP (IP / CIDR / dai / CSV)")
	flag.StringVar(&o.rulesFile, "rules", "artex-rules.json", "file dau hieu nhan dang ARTEX")
	flag.StringVar(&o.outDir, "out", "ket-qua", "thu muc ghi ket qua")
	flag.StringVar(&o.ports, "ports", "80,443,8787", "danh sach port, cach nhau bang dau phay")
	flag.IntVar(&o.concurrency, "c", 500, "so IP quet dong thoi")
	flag.IntVar(&o.rate, "rate", 0, "gioi han ket noi moi giay (0 = khong gioi han)")
	flag.DurationVar(&o.dialTimeout, "dial-timeout", 2*time.Second, "timeout bat tay TCP")
	flag.DurationVar(&o.httpTimeout, "http-timeout", 5*time.Second, "timeout mot request HTTP")
	flag.StringVar(&o.userAgent, "ua", "VinSOC-AssetDiscovery/1.0 (+lien he: SOC)", "User-Agent")
	flag.Int64Var(&o.maxBody, "max-body", 512*1024, "so byte body toi da doc moi response")
	flag.BoolVar(&o.allowLarge, "allow-large", false, "cho phep CIDR lon hon /16")
	flag.BoolVar(&o.resume, "resume", false, "bo qua cac IP da quet trong lan chay truoc")
	flag.BoolVar(&o.noShuffle, "no-shuffle", false, "giu nguyen thu tu IP (mac dinh xao tron de trai deu tai)")
	flag.BoolVar(&o.verbose, "v", false, "in ket qua khop ngay khi tim thay")
	flag.StringVar(&o.profileURL, "profile", "", "lay dau hieu tu mot URL ARTEX da biet roi sinh file rules")
	flag.Parse()

	if o.profileURL != "" {
		if err := runProfile(o); err != nil {
			fmt.Fprintln(os.Stderr, "loi:", err)
			os.Exit(1)
		}
		return
	}

	if o.targetsFile == "" {
		fmt.Fprintln(os.Stderr, "thieu -targets. Dung -h de xem huong dan.")
		os.Exit(2)
	}

	rs, err := loadRules(o.rulesFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loi doc rules:", err)
		os.Exit(1)
	}
	ports, err := parsePorts(o.ports)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loi:", err)
		os.Exit(1)
	}
	if o.concurrency < 1 {
		fmt.Fprintln(os.Stderr, "loi: -c phai lon hon 0")
		os.Exit(2)
	}
	if o.concurrency > 5000 {
		fmt.Fprintln(os.Stderr, "canh bao: -c tren 5000 de gay 'too many open files'. Nho chay 'ulimit -n 65535' truoc.")
	}
	ips, warns, err := parseTargets(o.targetsFile, o.allowLarge)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loi doc targets:", err)
		os.Exit(1)
	}
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "canh bao:", w)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "khong co IP nao de quet")
		os.Exit(1)
	}

	if o.resume {
		done := loadScanned(o.outDir)
		if len(done) > 0 {
			var left []string
			for _, ip := range ips {
				if _, ok := done[ip]; !ok {
					left = append(left, ip)
				}
			}
			fmt.Printf("resume: bo qua %d IP da quet, con lai %d\n", len(ips)-len(left), len(left))
			ips = left
		}
	}
	if len(ips) == 0 {
		fmt.Println("tat ca IP da duoc quet truoc do - khong con gi de lam")
		return
	}

	if !o.noShuffle {
		rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
	}

	w, err := newWriters(o.outDir, o.resume)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loi tao file ket qua:", err)
		os.Exit(1)
	}

	cl := newClient(o)
	lim := newLimiter(o.rate)
	c := &counters{}
	ctx := context.Background()
	start := time.Now()

	fmt.Printf("Quet %d IP x %d port (%s) | concurrency=%d | rules=%s (%d dau hieu, nguong=%d)\n",
		len(ips), len(ports), o.ports, o.concurrency, rs.Name, len(rs.Rules), rs.MinScore)

	// Bao tien do dinh ky
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		total := int64(len(ips))
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				d := atomic.LoadInt64(&c.ipsDone)
				el := time.Since(start).Seconds()
				rate := float64(d) / el
				var eta string
				if rate > 0 {
					eta = (time.Duration(float64(total-d)/rate) * time.Second).Truncate(time.Second).String()
				} else {
					eta = "?"
				}
				fmt.Printf("  ... %d/%d IP (%.0f IP/s) | port mo: %d | HTTP: %d | ARTEX: %d | nghi ngo: %d | con ~%s\n",
					d, total, rate, atomic.LoadInt64(&c.openPort), atomic.LoadInt64(&c.httpOK),
					atomic.LoadInt64(&c.hits), atomic.LoadInt64(&c.suspect), eta)
				w.flush()
			}
		}
	}()

	jobs := make(chan string, o.concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < o.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				scanIP(ctx, ip, ports, o, rs, cl, lim, w, c)
			}
		}()
	}
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	close(stop)

	// Dong file truoc roi moi ghi de artex.txt ban da sap xep.
	w.close()
	if err := w.rewriteSorted(o.outDir); err != nil {
		fmt.Fprintln(os.Stderr, "canh bao: khong sap xep duoc artex.txt:", err)
	}

	fmt.Printf("\nXong sau %s\n", time.Since(start).Truncate(time.Second))
	fmt.Printf("  IP da quet   : %d\n", atomic.LoadInt64(&c.ipsDone))
	fmt.Printf("  Port mo      : %d\n", atomic.LoadInt64(&c.openPort))
	fmt.Printf("  Co HTTP(S)   : %d\n", atomic.LoadInt64(&c.httpOK))
	fmt.Printf("  ARTEX        : %d  -> %s/artex.txt\n", atomic.LoadInt64(&c.hits), o.outDir)
	fmt.Printf("  Nghi ngo     : %d  -> loc verdict=suspect trong %s/results.csv\n", atomic.LoadInt64(&c.suspect), o.outDir)
}

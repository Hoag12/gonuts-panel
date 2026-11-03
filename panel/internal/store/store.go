// Package store holds the panel's persistent state: Discord users, browser
// sessions, one-shot pairing codes, installations with their last telemetry
// frame, and a bounded command audit.
//
// Everything lives in a single JSON file that is replaced atomically. A
// corrupt file is refused instead of being overwritten, and every read returns
// a copy so callers can never mutate the store's internal maps or pointers.
package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionTTL         = 30 * 24 * time.Hour
	codeTTL            = 5 * time.Minute
	commandTTL         = 7 * 24 * time.Hour
	maxCommands        = 1000
	maxCodeAttempts    = 5
	codeLength         = 8
	codeAlphabet       = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	credentialPrefix   = "gni1_"
	defaultInstallName = "GoNuts client"
	stateFileName      = "state.json"
)

// Pairing-code failures. Callers map them to HTTP status codes with errors.Is.
var (
	ErrNotFound = errors.New("store: pairing code not found")
	ErrUsed     = errors.New("store: pairing code already used")
	ErrExpired  = errors.New("store: pairing code expired")
	ErrAttempts = errors.New("store: too many pairing attempts")
)

type User struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	GlobalName string `json:"globalName,omitempty"`
	Avatar     string `json:"avatar,omitempty"`
	CreatedAt  int64  `json:"createdAt"`
}

type Session struct {
	DiscordID string `json:"discordId"`
	CSRF      string `json:"csrf"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

type Code struct {
	DiscordID string `json:"discordId"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Attempts  int    `json:"attempts"`
	UsedAt    int64  `json:"usedAt,omitempty"`
}

type Interval struct {
	H1     *int64 `json:"h1,omitempty"`
	H24    *int64 `json:"h24,omitempty"`
	Source string `json:"source,omitempty"`
}

type Swarm struct {
	Enabled         bool `json:"enabled"`
	GuidanceEnabled bool `json:"guidanceEnabled"`
	Eligible        bool `json:"eligible"`
}

type Controls struct {
	Pause    bool `json:"pause"`
	Resume   bool `json:"resume"`
	Snapshot bool `json:"snapshot"`
}

type Telemetry struct {
	At           int64     `json:"at"`
	State        string    `json:"state"`
	Detail       string    `json:"detail"`
	Account      string    `json:"account"`
	Listed       int64     `json:"listed"`
	Slots        int64     `json:"slots"`
	Bank         *int64    `json:"bank,omitempty"`
	Trades       int64     `json:"trades"`
	Profit       *Interval `json:"profit,omitempty"`
	Sales        *Interval `json:"sales,omitempty"`
	Purchases    *Interval `json:"purchases,omitempty"`
	Listings     *Interval `json:"listings,omitempty"`
	Reprices     *Interval `json:"reprices,omitempty"`
	Build        string    `json:"build"`
	LastAction   string    `json:"lastAction"`
	LastActionAt int64     `json:"lastActionAt"`
	MascotFace   string    `json:"mascotFace"`
	Swarm        *Swarm    `json:"swarm,omitempty"`
	Controls     *Controls `json:"controls,omitempty"`
}

type Installation struct {
	ID             int64      `json:"id"`
	DiscordID      string     `json:"discordId"`
	Name           string     `json:"name"`
	Build          string     `json:"build"`
	Hive           string     `json:"hive"`
	Capabilities   []string   `json:"capabilities"`
	CredentialHash string     `json:"credentialHash"`
	CreatedAt      int64      `json:"createdAt"`
	LastSeen       int64      `json:"lastSeen"`
	Telemetry      *Telemetry `json:"telemetry,omitempty"`
	Online         bool       `json:"online"`
}

type Command struct {
	ID             string `json:"id"`
	InstallationID int64  `json:"installationId"`
	DiscordID      string `json:"discordId"`
	Command        string `json:"command"`
	CreatedAt      int64  `json:"createdAt"`
	ExpiresAt      int64  `json:"expiresAt"`
	State          string `json:"state"`
	Reason         string `json:"reason,omitempty"`
}

type State struct {
	Users              map[string]*User         `json:"users"`
	Sessions           map[string]*Session      `json:"sessions"`
	Codes              map[string]*Code         `json:"codes"`
	Installations      map[string]*Installation `json:"installations"`
	Commands           map[string]*Command      `json:"commands"`
	NextInstallationID int64                    `json:"nextInstallationId"`
}

// Store serialises access to one state file. All methods are safe for
// concurrent use.
type Store struct {
	mu     sync.Mutex
	dir    string
	path   string
	data   State
	dirty  bool
	closed bool
}

// Open loads (or creates) the state file in dir. A file that exists but does
// not decode is reported as an error and left untouched; it is never reset.
func Open(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("store: data directory is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, path: filepath.Join(dir, stateFileName)}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.data = newState()
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(b); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("state.json is corrupt: expected a JSON object")
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("state.json is corrupt: %w", err)
	}
	s.data.ensure()
	if s.data.prune(time.Now()) {
		s.dirty = true
	}
	return s, nil
}

// SaveNow writes the current state to disk.
func (s *Store) SaveNow() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// Close flushes pending changes (for example telemetry) and releases the
// store. It is safe to call more than once.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.dirty {
		return s.saveLocked()
	}
	return nil
}

// CreateSession returns a new session token (stored hashed) and the CSRF token
// bound to it.
func (s *Store) CreateSession(discordID string, now time.Time) (token, csrf string, err error) {
	if discordID == "" {
		return "", "", errors.New("store: discord id is required")
	}
	token, err = RandomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = RandomToken(32)
	if err != nil {
		return "", "", err
	}
	sess := &Session{
		DiscordID: discordID,
		CSRF:      csrf,
		CreatedAt: now.UnixMilli(),
		ExpiresAt: now.Add(sessionTTL).UnixMilli(),
	}
	key := HashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Sessions[key] = sess
	if err := s.persistLocked(); err != nil {
		delete(s.data.Sessions, key)
		return "", "", err
	}
	return token, csrf, nil
}

// Session resolves a raw session token. Expired sessions are dropped.
func (s *Store) Session(token string, now time.Time) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	key := HashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data.Sessions[key]
	if !ok {
		return nil, false
	}
	if sess.ExpiresAt <= now.UnixMilli() {
		delete(s.data.Sessions, key)
		s.dirty = true
		return nil, false
	}
	cp := *sess
	return &cp, true
}

// DeleteSession removes the session for a raw token.
func (s *Store) DeleteSession(token string) error {
	if token == "" {
		return nil
	}
	key := HashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Sessions[key]; !ok {
		return nil
	}
	delete(s.data.Sessions, key)
	return s.persistLocked()
}

// UpsertUser stores the latest Discord profile for a user.
func (s *Store) UpsertUser(u User) error {
	if u.ID == "" {
		return errors.New("store: user id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.data.Users[u.ID]; ok && old != nil {
		if u.CreatedAt == 0 {
			u.CreatedAt = old.CreatedAt
		}
	}
	cp := u
	s.data.Users[u.ID] = &cp
	return s.persistLocked()
}

// User returns a copy of the stored user.
func (s *Store) User(id string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.data.Users[id]
	if !ok || u == nil {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// CreateCode replaces any live pairing code for the user and returns the new
// code formatted as ABCD-EFGH together with its expiry in unix milliseconds.
func (s *Store) CreateCode(discordID string, now time.Time) (string, int64, error) {
	if discordID == "" {
		return "", 0, errors.New("store: discord id is required")
	}
	code, err := randomCode()
	if err != nil {
		return "", 0, err
	}
	expiresAt := now.Add(codeTTL).UnixMilli()
	key := HashToken(code)
	c := &Code{
		DiscordID: discordID,
		CreatedAt: now.UnixMilli(),
		ExpiresAt: expiresAt,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, existing := range s.data.Codes {
		if existing == nil || existing.DiscordID == discordID {
			delete(s.data.Codes, k)
		}
	}
	s.data.Codes[key] = c
	if err := s.persistLocked(); err != nil {
		delete(s.data.Codes, key)
		return "", 0, err
	}
	return code[:4] + "-" + code[4:], expiresAt, nil
}

// RedeemCode consumes a pairing code and creates the installation it grants.
// The returned credential is shown once; only its hash is stored.
func (s *Store) RedeemCode(code, name, build, hive string, caps []string, now time.Time) (*Installation, string, error) {
	normalized, ok := NormalizeCode(code)
	if !ok {
		return nil, "", ErrNotFound
	}
	key := HashToken(normalized)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.data.Codes[key]
	if !ok || c == nil {
		return nil, "", ErrNotFound
	}
	if c.UsedAt > 0 {
		return nil, "", ErrUsed
	}
	if now.UnixMilli() >= c.ExpiresAt {
		delete(s.data.Codes, key)
		_ = s.persistLocked()
		return nil, "", ErrExpired
	}
	c.Attempts++
	if c.Attempts > maxCodeAttempts {
		delete(s.data.Codes, key)
		_ = s.persistLocked()
		return nil, "", ErrAttempts
	}

	credential, err := RandomToken(32)
	if err != nil {
		return nil, "", err
	}
	credential = credentialPrefix + credential

	id := s.data.NextInstallationID
	if id <= 0 {
		id = 1
	}
	s.data.NextInstallationID = id + 1
	c.UsedAt = now.UnixMilli()

	inst := &Installation{
		ID:             id,
		DiscordID:      c.DiscordID,
		Name:           installName(name),
		Build:          strings.TrimSpace(build),
		Hive:           strings.TrimSpace(hive),
		Capabilities:   append([]string{}, caps...),
		CredentialHash: HashToken(credential),
		CreatedAt:      now.UnixMilli(),
		LastSeen:       now.UnixMilli(),
	}
	instKey := installationKey(id)
	s.data.Installations[instKey] = inst
	if err := s.persistLocked(); err != nil {
		delete(s.data.Installations, instKey)
		return nil, "", err
	}
	return cloneInstallation(inst), credential, nil
}

// Installation returns a copy of one installation.
func (s *Store) Installation(id int64) (*Installation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.data.Installations[installationKey(id)]
	if !ok || inst == nil {
		return nil, false
	}
	return cloneInstallation(inst), true
}

// InstallationByCredential looks up an installation by the hash of its
// bearer credential. The raw credential never reaches the store.
func (s *Store) InstallationByCredential(hash string) (*Installation, bool) {
	if hash == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.data.Installations {
		if inst != nil && inst.CredentialHash == hash {
			return cloneInstallation(inst), true
		}
	}
	return nil, false
}

// InstallationsFor returns copies of a user's installations, oldest first.
func (s *Store) InstallationsFor(discordID string) []*Installation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Installation, 0, len(s.data.Installations))
	for _, inst := range s.data.Installations {
		if inst != nil && inst.DiscordID == discordID {
			out = append(out, cloneInstallation(inst))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SetOnline records connection presence and persists immediately.
func (s *Store) SetOnline(id int64, online bool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.data.Installations[installationKey(id)]
	if !ok || inst == nil {
		return ErrNotFound
	}
	inst.Online = online
	if ms := now.UnixMilli(); ms > inst.LastSeen {
		inst.LastSeen = ms
	}
	return s.persistLocked()
}

// SetTelemetry keeps the latest telemetry frame for an installation. The
// change is only marked dirty; it is written by SaveNow or Close.
func (s *Store) SetTelemetry(id int64, t *Telemetry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.data.Installations[installationKey(id)]
	if !ok || inst == nil {
		return ErrNotFound
	}
	inst.Telemetry = CloneTelemetry(t)
	if ms := now.UnixMilli(); ms > inst.LastSeen {
		inst.LastSeen = ms
	}
	s.dirty = true
	return nil
}

// RenameInstallation changes the display name of an installation owned by
// discordID.
func (s *Store) RenameInstallation(id int64, discordID, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("store: installation name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.data.Installations[installationKey(id)]
	if !ok || inst == nil || inst.DiscordID != discordID {
		return ErrNotFound
	}
	inst.Name = name
	return s.persistLocked()
}

// DeleteInstallation removes an installation owned by discordID together with
// its command history.
func (s *Store) DeleteInstallation(id int64, discordID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := installationKey(id)
	inst, ok := s.data.Installations[key]
	if !ok || inst == nil || inst.DiscordID != discordID {
		return ErrNotFound
	}
	delete(s.data.Installations, key)
	for k, c := range s.data.Commands {
		if c == nil || c.InstallationID == id {
			delete(s.data.Commands, k)
		}
	}
	return s.persistLocked()
}

// AddCommand records a command sent to an installation.
func (s *Store) AddCommand(c Command) error {
	if c.ID == "" {
		return errors.New("store: command id is required")
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = time.Now().UnixMilli()
	}
	if c.ExpiresAt == 0 {
		c.ExpiresAt = c.CreatedAt + 30_000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := c
	s.data.Commands[c.ID] = &cp
	s.data.pruneCommands(time.Now())
	return s.persistLocked()
}

// UpdateCommand moves a command to a new state, keeping the reason when one is
// supplied.
func (s *Store) UpdateCommand(id, state, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.data.Commands[id]
	if !ok || c == nil {
		return ErrNotFound
	}
	c.State = state
	if reason != "" {
		c.Reason = reason
	}
	return s.persistLocked()
}

// LastCommand returns a copy of the newest command for an installation, or nil
// when the installation has none.
func (s *Store) LastCommand(installationID int64) *Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	var newest *Command
	for _, c := range s.data.Commands {
		if c == nil || c.InstallationID != installationID {
			continue
		}
		if newest == nil || c.CreatedAt > newest.CreatedAt ||
			(c.CreatedAt == newest.CreatedAt && c.ID > newest.ID) {
			newest = c
		}
	}
	if newest == nil {
		return nil
	}
	cp := *newest
	return &cp
}

// State returns a deep copy of the whole store. It exists for tests and
// diagnostics; request paths use the scoped accessors instead.
func (s *Store) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := State{
		Users:              make(map[string]*User, len(s.data.Users)),
		Sessions:           make(map[string]*Session, len(s.data.Sessions)),
		Codes:              make(map[string]*Code, len(s.data.Codes)),
		Installations:      make(map[string]*Installation, len(s.data.Installations)),
		Commands:           make(map[string]*Command, len(s.data.Commands)),
		NextInstallationID: s.data.NextInstallationID,
	}
	for k, u := range s.data.Users {
		if u != nil {
			cp := *u
			out.Users[k] = &cp
		}
	}
	for k, sess := range s.data.Sessions {
		if sess != nil {
			cp := *sess
			out.Sessions[k] = &cp
		}
	}
	for k, c := range s.data.Codes {
		if c != nil {
			cp := *c
			out.Codes[k] = &cp
		}
	}
	for k, inst := range s.data.Installations {
		if inst != nil {
			out.Installations[k] = cloneInstallation(inst)
		}
	}
	for k, c := range s.data.Commands {
		if c != nil {
			cp := *c
			out.Commands[k] = &cp
		}
	}
	return out
}

// saveLocked writes the state atomically: temp file in the same directory,
// fsync, rename, then a best-effort directory sync. The caller must hold mu.
func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode state: %w", err)
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("store: create state temp: %w", err)
	}
	tmp := f.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: chmod state temp: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: write state temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: sync state temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: close state temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("store: replace state: %w", err)
	}
	renamed = true
	if d, err := os.Open(s.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	s.dirty = false
	return nil
}

// persistLocked saves immediately and retries on Close if the write failed.
func (s *Store) persistLocked() error {
	if err := s.saveLocked(); err != nil {
		s.dirty = true
		return err
	}
	return nil
}

func newState() State {
	return State{
		Users:              map[string]*User{},
		Sessions:           map[string]*Session{},
		Codes:              map[string]*Code{},
		Installations:      map[string]*Installation{},
		Commands:           map[string]*Command{},
		NextInstallationID: 1,
	}
}

// ensure repairs partially empty or stale state after decoding.
func (st *State) ensure() {
	if st.Users == nil {
		st.Users = map[string]*User{}
	}
	if st.Sessions == nil {
		st.Sessions = map[string]*Session{}
	}
	if st.Codes == nil {
		st.Codes = map[string]*Code{}
	}
	if st.Installations == nil {
		st.Installations = map[string]*Installation{}
	}
	if st.Commands == nil {
		st.Commands = map[string]*Command{}
	}
	for k, v := range st.Users {
		if v == nil {
			delete(st.Users, k)
		}
	}
	for k, v := range st.Sessions {
		if v == nil {
			delete(st.Sessions, k)
		}
	}
	for k, v := range st.Codes {
		if v == nil {
			delete(st.Codes, k)
		}
	}
	for k, v := range st.Commands {
		if v == nil {
			delete(st.Commands, k)
		}
	}
	maxID := int64(0)
	for k, inst := range st.Installations {
		if inst == nil || inst.ID <= 0 {
			delete(st.Installations, k)
			continue
		}
		if inst.ID > maxID {
			maxID = inst.ID
		}
		if key := installationKey(inst.ID); key != k {
			delete(st.Installations, k)
			st.Installations[key] = inst
		}
	}
	if st.NextInstallationID <= maxID {
		st.NextInstallationID = maxID + 1
	}
	if st.NextInstallationID <= 0 {
		st.NextInstallationID = 1
	}
}

// prune drops expired sessions and codes plus stale commands. It reports
// whether anything was removed.
func (st *State) prune(now time.Time) bool {
	nowMS := now.UnixMilli()
	changed := false
	for k, sess := range st.Sessions {
		if sess == nil || sess.ExpiresAt <= nowMS {
			delete(st.Sessions, k)
			changed = true
		}
	}
	for k, c := range st.Codes {
		if c == nil || c.ExpiresAt <= nowMS {
			delete(st.Codes, k)
			changed = true
		}
	}
	if st.pruneCommands(now) {
		changed = true
	}
	return changed
}

// pruneCommands enforces the age and ring-size limits on the command audit.
func (st *State) pruneCommands(now time.Time) bool {
	changed := false
	cutoff := now.Add(-commandTTL).UnixMilli()
	for k, c := range st.Commands {
		if c == nil || c.CreatedAt < cutoff {
			delete(st.Commands, k)
			changed = true
		}
	}
	if len(st.Commands) > maxCommands {
		type entry struct {
			id string
			at int64
		}
		entries := make([]entry, 0, len(st.Commands))
		for k, c := range st.Commands {
			entries = append(entries, entry{id: k, at: c.CreatedAt})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].at != entries[j].at {
				return entries[i].at < entries[j].at
			}
			return entries[i].id < entries[j].id
		})
		for _, e := range entries[:len(entries)-maxCommands] {
			delete(st.Commands, e.id)
			changed = true
		}
	}
	return changed
}

// NormalizeCode canonicalises a human-typed pairing code: upper case, drop
// dashes and spaces, and fold the common 0/O and 1/I/L confusions.
func NormalizeCode(in string) (string, bool) {
	var b strings.Builder
	b.Grow(codeLength)
	for _, r := range strings.ToUpper(strings.TrimSpace(in)) {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		case r == '0':
			b.WriteByte('O')
		case r == '1' || r == 'I':
			b.WriteByte('L')
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) != codeLength {
		return "", false
	}
	for i := 0; i < len(out); i++ {
		c := out[i]
		if (c < 'A' || c > 'Z') && (c < '2' || c > '9') {
			return "", false
		}
	}
	return out, true
}

// RandomToken returns n cryptographically random bytes as unpadded base64url.
func RandomToken(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("store: token size must be positive")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is the hex SHA-256 used for session tokens, pairing codes, and
// installation credentials.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CloneTelemetry deep-copies a telemetry frame, including its nested intervals,
// swarm flags, and control flags.
func CloneTelemetry(in *Telemetry) *Telemetry {
	if in == nil {
		return nil
	}
	out := *in
	if in.Bank != nil {
		v := *in.Bank
		out.Bank = &v
	}
	out.Profit = cloneInterval(in.Profit)
	out.Sales = cloneInterval(in.Sales)
	out.Purchases = cloneInterval(in.Purchases)
	out.Listings = cloneInterval(in.Listings)
	out.Reprices = cloneInterval(in.Reprices)
	if in.Swarm != nil {
		v := *in.Swarm
		out.Swarm = &v
	}
	if in.Controls != nil {
		v := *in.Controls
		out.Controls = &v
	}
	return &out
}

func cloneInterval(in *Interval) *Interval {
	if in == nil {
		return nil
	}
	out := *in
	if in.H1 != nil {
		v := *in.H1
		out.H1 = &v
	}
	if in.H24 != nil {
		v := *in.H24
		out.H24 = &v
	}
	return &out
}

func cloneInstallation(in *Installation) *Installation {
	if in == nil {
		return nil
	}
	out := *in
	out.Capabilities = append([]string{}, in.Capabilities...)
	out.Telemetry = CloneTelemetry(in.Telemetry)
	return &out
}

// randomCode draws codeLength characters uniformly from codeAlphabet. The
// alphabet is 32 characters long, so masking a random byte with 31 is unbiased.
func randomCode() (string, error) {
	raw := make([]byte, codeLength)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: read random: %w", err)
	}
	out := make([]byte, codeLength)
	for i := range raw {
		out[i] = codeAlphabet[raw[i]&31]
	}
	return string(out), nil
}

func installName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return defaultInstallName
	}
	return name
}

func installationKey(id int64) string {
	return strconv.FormatInt(id, 10)
}

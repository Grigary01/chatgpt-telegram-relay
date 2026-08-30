package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	sessionCookieName = "relay_session"
	sessionTTL        = 12 * time.Hour
)

type inlineKeyboardButton struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

type inlineKeyboardMarkup struct {
	InlineKeyboard [][]inlineKeyboardButton `json:"inline_keyboard"`
}

type telegramRequest struct {
	ChatID                string                `json:"chat_id"`
	Text                  string                `json:"text"`
	DisableWebPagePreview bool                  `json:"disable_web_page_preview"`
	ReplyMarkup           *inlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

type actionButton struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

type inputPayload struct {
	Key     string         `json:"key,omitempty"`
	Text    string         `json:"text,omitempty"`
	Buttons []actionButton `json:"buttons,omitempty"`
}

var telegramAPIBase = "https://api.telegram.org"
var telegramHTTPClient = &http.Client{Timeout: 8 * time.Second}

func Handler(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if action == "" {
		action = "send"
	}

	if action == "health" {
		handleHealth(w, r)
		return
	}

	// Compatibility transport for ChatGPT Automations / Vercel URL fetch.
	// Browser usage remains POST + signed HttpOnly session.
	if action == "send" && r.Method == http.MethodGet {
		handleQuerySend(w, r)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch action {
	case "login":
		handleLogin(w, r)
	case "logout":
		handleLogout(w)
	case "send":
		handleSend(w, r)
	default:
		http.Error(w, "unknown action", http.StatusNotFound)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":            true,
		"configured":    credentialsConfigured(),
		"authenticated": authenticated(r),
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if relayKey() == "" {
		http.Error(w, "server is not configured", http.StatusInternalServerError)
		return
	}
	input, ok := decodeInput(w, r, 4<<10)
	if !ok {
		return
	}
	if !validRelayKey(input.Key) {
		time.Sleep(300 * time.Millisecond)
		http.Error(w, "invalid access key", http.StatusUnauthorized)
		return
	}
	session, err := newSessionValue(time.Now())
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, session)
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleLogout(w http.ResponseWriter) {
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	if !credentialsConfigured() {
		http.Error(w, "server is not configured", http.StatusInternalServerError)
		return
	}
	if !authenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	input, ok := decodeInput(w, r, 32<<10)
	if !ok {
		return
	}
	processSend(w, r, input)
}

func handleQuerySend(w http.ResponseWriter, r *http.Request) {
	if !credentialsConfigured() {
		http.Error(w, "server is not configured", http.StatusInternalServerError)
		return
	}

	providedKey := r.URL.Query().Get("key")
	if !validRelayKey(providedKey) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	q := r.URL.Query()
	buttons := make([]actionButton, 0, 3)
	for _, pair := range [][2]string{{"button", "url"}, {"button2", "url2"}, {"button3", "url3"}} {
		buttonText := strings.TrimSpace(q.Get(pair[0]))
		buttonURL := strings.TrimSpace(q.Get(pair[1]))
		if buttonText == "" && buttonURL == "" {
			continue
		}
		if buttonText == "" {
			buttonText = "Открыть"
		}
		buttons = append(buttons, actionButton{Text: buttonText, URL: buttonURL})
	}

	processSend(w, r, inputPayload{
		Text:    q.Get("text"),
		Buttons: buttons,
	})
}

func processSend(w http.ResponseWriter, r *http.Request, input inputPayload) {
	text := strings.TrimSpace(input.Text)
	if text == "" {
		http.Error(w, "message is empty", http.StatusBadRequest)
		return
	}
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > 3500 {
		http.Error(w, "message is too long or invalid", http.StatusBadRequest)
		return
	}

	rows, err := buildButtons(input.Buttons)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var replyMarkup *inlineKeyboardMarkup
	if len(rows) > 0 {
		replyMarkup = &inlineKeyboardMarkup{InlineKeyboard: rows}
	}

	payload, err := json.Marshal(telegramRequest{
		ChatID:                strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")),
		Text:                  text,
		DisableWebPagePreview: true,
		ReplyMarkup:           replyMarkup,
	})
	if err != nil {
		http.Error(w, "failed to build telegram request", http.StatusInternalServerError)
		return
	}

	endpoint := telegramAPIBase + "/bot" + strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")) + "/sendMessage"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "failed to create telegram request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := telegramHTTPClient.Do(req)
	if err != nil {
		http.Error(w, "telegram request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		http.Error(w, "failed to read telegram response", http.StatusBadGateway)
		return
	}

	var tg telegramResponse
	_ = json.Unmarshal(body, &tg)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !tg.OK {
		msg := "Telegram rejected the message"
		if tg.Description != "" {
			msg += ": " + tg.Description
		}
		http.Error(w, msg, http.StatusBadGateway)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func decodeInput(w http.ResponseWriter, r *http.Request, limit int64) (inputPayload, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	var input inputPayload
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return inputPayload{}, false
	}
	return input, true
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	scheme := "https"
	if r.Header.Get("X-Forwarded-Proto") == "http" || (r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "") {
		scheme = "http"
	}
	expected := scheme + "://" + r.Host
	return hmac.Equal([]byte(origin), []byte(expected))
}

func relayKey() string {
	return strings.TrimSpace(os.Getenv("RELAY_KEY"))
}

func credentialsConfigured() bool {
	return relayKey() != "" && strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")) != "" && strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")) != ""
}

func validRelayKey(provided string) bool {
	expected := relayKey()
	provided = strings.TrimSpace(provided)
	if expected == "" || len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func newSessionValue(now time.Time) (string, error) {
	if relayKey() == "" {
		return "", fmt.Errorf("missing relay key")
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := strconv.FormatInt(now.Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(nonce)
	mac := hmac.New(sha256.New, []byte(relayKey()))
	_, _ = mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

func validSessionValue(value string, now time.Time) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || relayKey() == "" {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	issuedAt := time.Unix(ts, 0)
	if issuedAt.After(now.Add(2*time.Minute)) || now.Sub(issuedAt) > sessionTTL {
		return false
	}
	payload := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(relayKey()))
	_, _ = mac.Write([]byte(payload))
	expected, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	return hmac.Equal(mac.Sum(nil), expected)
}

func authenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return validSessionValue(cookie.Value, time.Now())
}

func setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: value, Path: "/", MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func buildButtons(buttons []actionButton) ([][]inlineKeyboardButton, error) {
	if len(buttons) > 3 {
		return nil, fmt.Errorf("too many buttons")
	}
	rows := make([][]inlineKeyboardButton, 0, len(buttons))
	for _, button := range buttons {
		actionURL := strings.TrimSpace(button.URL)
		buttonText := strings.TrimSpace(button.Text)
		if actionURL == "" && buttonText == "" {
			continue
		}
		if actionURL == "" {
			return nil, fmt.Errorf("button url is required")
		}
		if buttonText == "" {
			buttonText = "Открыть"
		}
		if !utf8.ValidString(buttonText) || utf8.RuneCountInString(buttonText) > 64 {
			return nil, fmt.Errorf("button text is too long or invalid")
		}
		parsed, err := url.Parse(actionURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || len(actionURL) > 2048 {
			return nil, fmt.Errorf("invalid action url")
		}
		rows = append(rows, []inlineKeyboardButton{{Text: buttonText, URL: actionURL}})
	}
	return rows, nil
}

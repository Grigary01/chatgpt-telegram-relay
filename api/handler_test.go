package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func configureTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RELAY_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("TELEGRAM_CHAT_ID", "123456")
}

func authCookie(t *testing.T) *http.Cookie {
	t.Helper()
	session, err := newSessionValue(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookieName, Value: session}
}

func request(t *testing.T, method, target, body string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "relay.test"
	req.Header.Set("Origin", "https://relay.test")
	rec := httptest.NewRecorder()
	return rec, req
}

func TestLoginRejectsWrongKey(t *testing.T) {
	configureTestEnv(t)
	rec, req := request(t, http.MethodPost, "https://relay.test/api/send?action=login", `{"key":"wrong"}`)
	Handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLoginSetsSecureSessionCookie(t *testing.T) {
	configureTestEnv(t)
	rec, req := request(t, http.MethodPost, "https://relay.test/api/send?action=login", `{"key":"0123456789abcdef0123456789abcdef"}`)
	Handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie: %#v", cookies)
	}
}

func TestSendRequiresAuthentication(t *testing.T) {
	configureTestEnv(t)
	rec, req := request(t, http.MethodPost, "https://relay.test/api/send?action=send", `{"text":"hello"}`)
	Handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSendRejectsCrossOrigin(t *testing.T) {
	configureTestEnv(t)
	rec, req := request(t, http.MethodPost, "https://relay.test/api/send?action=send", `{"text":"hello"}`)
	req.Header.Set("Origin", "https://evil.test")
	req.AddCookie(authCookie(t))
	Handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSendRejectsInvalidURL(t *testing.T) {
	configureTestEnv(t)
	rec, req := request(t, http.MethodPost, "https://relay.test/api/send?action=send", `{"text":"hello","buttons":[{"text":"bad","url":"http://example.com"}]}`)
	req.AddCookie(authCookie(t))
	Handler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSendSuccessUsesTelegramPayload(t *testing.T) {
	configureTestEnv(t)
	var got telegramRequest
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer tg.Close()
	oldBase, oldClient := telegramAPIBase, telegramHTTPClient
	telegramAPIBase, telegramHTTPClient = tg.URL, tg.Client()
	defer func() { telegramAPIBase, telegramHTTPClient = oldBase, oldClient }()

	rec, req := request(t, http.MethodPost, "https://relay.test/api/send?action=send", `{"text":"hello","buttons":[{"text":"Open","url":"https://example.com"}]}`)
	req.AddCookie(authCookie(t))
	Handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if got.ChatID != "123456" || got.Text != "hello" || got.ReplyMarkup == nil || len(got.ReplyMarkup.InlineKeyboard) != 1 {
		t.Fatalf("unexpected telegram payload: %#v", got)
	}
}

func TestGetSendRejectsMissingKey(t *testing.T) {
	configureTestEnv(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://relay.test/api/send?text=hello", nil)
	Handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetSendSuccessUsesTelegramPayload(t *testing.T) {
	configureTestEnv(t)
	var got telegramRequest
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer tg.Close()
	oldBase, oldClient := telegramAPIBase, telegramHTTPClient
	telegramAPIBase, telegramHTTPClient = tg.URL, tg.Client()
	defer func() { telegramAPIBase, telegramHTTPClient = oldBase, oldClient }()

	target := "https://relay.test/api/send?key=0123456789abcdef0123456789abcdef&text=hello&button=Open&url=https%3A%2F%2Fexample.com"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	Handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if got.ChatID != "123456" || got.Text != "hello" || got.ReplyMarkup == nil || len(got.ReplyMarkup.InlineKeyboard) != 1 {
		t.Fatalf("unexpected telegram payload: %#v", got)
	}
	if got.ReplyMarkup.InlineKeyboard[0][0].Text != "Open" || got.ReplyMarkup.InlineKeyboard[0][0].URL != "https://example.com" {
		t.Fatalf("unexpected button: %#v", got.ReplyMarkup.InlineKeyboard[0][0])
	}
}

func TestHealthDoesNotExposeSecrets(t *testing.T) {
	configureTestEnv(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://relay.test/api/send?action=health", nil)
	Handler(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "test-token") || strings.Contains(body, "0123456789abcdef") {
		t.Fatal("health response leaked a secret")
	}
}

package router

import (
	"bytes"
	"github.com/gofiber/fiber/v3"
	"net/http/httptest"
	"testing"
)

func TestJSONInterpretationCannotChangeUnderUnsignedHeader(t *testing.T) {
	app := fiber.New()
	app.Use(requireJSON)
	app.All("/*", func(c fiber.Ctx) error { return c.SendStatus(204) })
	for _, tc := range []struct {
		method, contentType string
		status              int
	}{{"POST", "application/json", 204}, {"POST", "application/json; charset=utf-8", 204}, {"POST", "application/x-www-form-urlencoded", 415}, {"POST", "", 415}, {"POST", "application/json; broken", 415}, {"GET", "", 204}} {
		req := httptest.NewRequest(tc.method, "/v1/revoke", bytes.NewBufferString(`{"subject":"test&subject=other&x="}`))
		if tc.contentType != "" {
			req.Header.Set("Content-Type", tc.contentType)
		}
		response, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s %s: status %d", tc.method, tc.contentType, response.StatusCode)
		}
	}
}

package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"

	"github.com/labstack/echo/v4"
)

func ValidateHMAC(secret string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Extract the HMAC from headers
			clientHMAC := c.Request().Header.Get("X-HMAC-Signature")
			if clientHMAC == "" {
				return c.JSONBlob(http.StatusUnauthorized, []byte(`{"error": "missing HMAC signature"}`))
			}

			// Read the body (this will be an io.ReadCloser, so ensure you read it only once!)
			bodyBytes, err := ioutil.ReadAll(c.Request().Body)
			if err != nil {
				return c.JSONBlob(http.StatusBadRequest, []byte(`{"error": "invalid body"}`))
			}

			// Restore the io.ReadCloser to its original state
			c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

			// Compute server's version of HMAC
			serverHMAC := computeHMAC(secret, bodyBytes)

			// Check if the HMACs match
			if clientHMAC != serverHMAC {
				return c.JSONBlob(http.StatusUnauthorized, []byte(`{"error": "invalid HMAC signature"}`))
			}

			// If all's well, proceed to the next middleware or the handler
			return next(c)
		}
	}
}

func computeHMAC(secret string, data []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

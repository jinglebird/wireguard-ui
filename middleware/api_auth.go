package middleware

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

func ValidateApi(secret string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := c.Request().Header.Get("x-api-key")
			if apiKey != secret {
				return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
			}
			return next(c)
		}
	}
}

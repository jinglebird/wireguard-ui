package router

import (
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/middleware"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
	"os"
)

func SetupAPIRoutes(app *echo.Echo, db store.IStore) {
	secret := os.Getenv("ADMIN_KEY")
	apiGroup := app.Group(util.BasePath + "/api")
	apiGroup.Use(middleware.ValidateHMAC(secret))

	app.POST(util.BasePath+"/new-client", handler.NewClient(db), handler.ContentTypeJson)
	app.POST(util.BasePath+"/remove-client", handler.RemoveClient(db), handler.ContentTypeJson)
}

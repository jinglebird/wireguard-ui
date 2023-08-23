package router

import (
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/middleware"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
	"io/fs"
	"os"
)

func SetupAPIRoutes(app *echo.Echo, db store.IStore, tmplDir fs.FS) {
	secret := os.Getenv("ADMIN_KEY")
	apiGroup := app.Group(util.BasePath + "/api")
	apiGroup.Use(middleware.ValidateApi(secret))

	app.POST(util.BasePath+"/api/new-client", handler.NewClientWithApi(db, tmplDir), handler.ContentTypeJson)
	app.POST(util.BasePath+"/api/remove-client", handler.RemoveClient(db), handler.ContentTypeJson)
}

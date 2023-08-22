package router

import (
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

func SetupAPIRoutes(app *echo.Echo, db store.IStore) {
	app.POST(util.BasePath+"/api/new-client", handler.NewClient(db), handler.ValidApi, handler.ContentTypeJson)
	app.POST(util.BasePath+"/api/remove-client", handler.RemoveClient(db), handler.ValidApi, handler.ContentTypeJson)
}

package main

import (
	"embed"
	"log"

	"SigmaVPN/internal/service"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	vpnService := service.NewVPNService()

	app := application.New(application.Options{
		Name:        "SigmaVPN",
		Description: "Учебный VPN-клиент",
		Services: []application.Service{
			application.NewService(vpnService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "SigmaVPN",
		Width:  900,
		Height: 600,
		URL:    "/",
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/imlgw/ylang/internal/config"
	"github.com/imlgw/ylang/internal/proxy/lan"
	"net"
	"net/http"
)

func Start(addr string) error {
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if err := http.Serve(listen, configRouter()); err != nil {
		return err
	}
	return nil
}

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/config", getConfigs)
	r.Put("/config", updateConfigs)
	return r
}

func updateConfigs(writer http.ResponseWriter, request *http.Request) {
	newConfig := &config.Client{}
	err := render.DecodeJSON(request.Body, newConfig)
	if err != nil {
		render.Status(request, http.StatusBadRequest)
		render.JSON(writer, request, newError("req invalid", err.Error()))
		return
	}
	newProxy, err := lan.NewLanProxy(newConfig)
	if err != nil {
		render.Status(request, http.StatusBadRequest)
		render.JSON(writer, request, newError("init proxy error", err.Error()))
		return
	}
	lan.Proxies() <- newProxy
	// TODO: 关闭旧proxy
}

func getConfigs(writer http.ResponseWriter, request *http.Request) {
	cfg := &config.Client{
		NicName:         lan.GetNicName(),
		Mode:            lan.GetMode(),
		TargetIP:        lan.GetTargetIP(),
		TargetGatewayIP: lan.GetTargetGatewayIP(),
		ServerIP:        lan.GetServerIP(),
		ServerPort:      lan.GetServerPort(),
	}
	render.JSON(writer, request, cfg)
}

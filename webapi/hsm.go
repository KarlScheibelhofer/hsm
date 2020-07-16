package main

import (
	"net/http"
	"os"
	"sync"
	"time"

	// "github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	"github.com/karlscheibelhofer/hsm"
	"github.com/karlscheibelhofer/hsm/keys"

	log "github.com/sirupsen/logrus"
)

var wg sync.WaitGroup
var router *gin.Engine

func init() {
	wg.Add(2)

	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	// Output to stdout instead of the default stderr
	log.SetOutput(os.Stdout)

	// log the debug severity or above.
	log.SetLevel(log.DebugLevel)

	// setup request router
	router = setupRouter()
}

func setupRouter() *gin.Engine {
	router := gin.Default()

	router.POST("/keys", keys.GenerateNewKey)
	router.POST("/keys/:id", keys.GenerateKey)
	router.GET("/keys/:id", keys.GetKey)
	router.GET("/keys", keys.ListKeys)

	return router
}

// StartHTTPServer starts the HTTP server listening on the specified interface:port.
// Set ":0" to listen on an arbitrary free port, which you can get
func StartHTTPServer(address string) (*http.Server, error) {
	return hsm.StartHTTPServer(address, router, &wg)
}

// StartHTTPSServer starts the HTTPS server listening on the specified interface:port.
// Set ":0" to listen on an arbitrary free port, which you can get
func StartHTTPSServer(address string) (*http.Server, error) {
	return hsm.StartHTTPSServer(address, router, &wg)
}

func main() {
	// start plain HTTP (for development/debugging)
	httpServer, err := StartHTTPServer(":8080")
	if err != nil {
		log.Fatal("unable to open listener", err)
		panic(err)
	}

	log.Info("HTTP server listening at address ", httpServer.Addr)

	// start strict HTTPS (for production)
	httpsServer, err := StartHTTPSServer(":8443")
	if err != nil {
		log.Fatal("unable to open listener", err)
		panic(err)
	}
	log.Info("HTTPS server listening at address ", httpsServer.Addr)

	// wait for servers to return/finish
	wg.Wait()
}

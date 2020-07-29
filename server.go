package hsm

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// StartHTTPServer starts the HTTP server listening on the specified interface:port.
// Set ":0" to listen on an arbitrary free port, which you can get
// from the Addr field of the returned server.
func StartHTTPServer(address string, router *gin.Engine, wg *sync.WaitGroup) (*http.Server, error) {
	// open listener before goroutine to ensure listener is ready when this function returns
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("unable to open listener", err)
		return nil, err
	}

	// read back address because port may be chosen by os if 0 was specified
	effectiveAddress := listener.Addr().String()
	httpServer := HTTPServer(effectiveAddress, router)

	go func() {
		defer wg.Done()
		log.Debug("starting HTTP server at address ", effectiveAddress)
		httpServer.Serve(listener)
	}()

	return httpServer, nil
}

// StartHTTPSServer starts the HTTP server listening on the specified interface:port.
// Set ":0" to listen on an arbitrary free port, which you can get
// from the Addr field of the returned server.
func StartHTTPSServer(address string, router *gin.Engine, wg *sync.WaitGroup) (*http.Server, error) {
	// open listener before goroutine to ensure listener is ready when this function returns
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("unable to open listener", err)
		return nil, err
	}

	// read back address because port may be chosen by os if 0 was specified
	effectiveAddress := listener.Addr().String()
	httpsServer := HTTPSServer(effectiveAddress, router)

	go func() {
		defer wg.Done()
		log.Debug("starting HTTPS server at address ", effectiveAddress)
		httpsServer.ServeTLS(listener, "server.rsa.crt", "server.rsa.key")
	}()

	return httpsServer, nil
}

//HTTPServer creates an http.Server structure
func HTTPServer(address string, router *gin.Engine) *http.Server {
	srv := &http.Server{
		Addr:         address,
		Handler:      router,
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
	}
	return srv
}

//HTTPSServer creates an http.Server structure for a HTTPS enables server
func HTTPSServer(address string, router *gin.Engine) *http.Server {
	//	mux := http.NewServeMux()
	//    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
	//        w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	//        w.Write([]byte("This is an example server.\n"))
	//    })
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			//            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			//            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         address,
		Handler:      router,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
	}
	return srv
}

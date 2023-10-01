package main

import (
	"context"
	"examplecontrolplane/syncx"
	"fmt"
	"github.com/danthegoodman1/Gildra/acme_http"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/samber/lo"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	httpChallenges = syncx.NewMap[string, string]()

	CADirURL = lo.Ternary(os.Getenv("CA_DIR") == "", "https://acme-staging-v02.api.letsencrypt.org/directory", os.Getenv("CA_DIR"))
	CAEmail  = os.Getenv("CA_EMAIL")
)

func main() {
	if CAEmail == "" {
		log.Fatal("Need to set the CA_EMAIL env var!")
	}

	server := echo.New()
	server.HideBanner = true
	server.HidePort = true
	server.HTTPErrorHandler = customHTTPErrorHandler
	log.Println("starting example control plane on :8080")

	logConfig := middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339_nano}","id":"${id}","remote_ip":"${remote_ip}",` +
			`"host":"${host}","method":"${method}","uri":"${uri}","user_agent":"${user_agent}",` +
			`"status":${status},"error":"${error}","latency":${latency},"latency_human":"${latency_human}",` +
			`"bytes_in":${bytes_in},"bytes_out":${bytes_out},"proto":"${protocol}",` +
			// fake request headers for getting info into http logs
			`"userID":"${header:loguserid}","reqID":"${header:reqID}","wasCached":"${header:wasCached}"}` + "\n",
		CustomTimeFormat: "2006-01-02 15:04:05.00000",
		Output:           os.Stdout, // logger or os.Stdout
	}
	server.Use(middleware.LoggerWithConfig(logConfig))
	server.GET("/echo", echoHandler)
	server.POST("/create_cert", createCert)
	server.GET("/domains/:domain/token/:token", getKey)
	server.GET("/domains/:domain/cert", getCert)
	server.GET("/domains/:domain/config", getConfig)

	go func() {
		err := server.Start(":8080")
		if err != nil {
			log.Fatalln("error starting server: ", err.Error())
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("stopping example control plane")
}

func customHTTPErrorHandler(err error, c echo.Context) {
	log.Println("Error handling request: ", err.Error())
	if err := c.String(http.StatusInternalServerError, err.Error()); err != nil {
		c.Logger().Error(err)
	}
}

// echoHandler echos back HTTP info of the incoming request
func echoHandler(c echo.Context) error {
	s := strings.Builder{}
	s.WriteString("HTTP Request:\n")
	s.WriteString("\n")
	s.WriteString("\tProto: " + c.Request().Proto)
	s.WriteString("\n")
	s.WriteString("\tHeaders:\n")
	for key, vals := range c.Request().Header {
		for _, val := range vals {
			s.WriteString(fmt.Sprintf("\t\t%s: %s\n", key, val))
		}
	}
	s.WriteString("\n")
	s.WriteString("\tQuery:\n")
	for key, vals := range c.Request().URL.Query() {
		for _, val := range vals {
			s.WriteString(fmt.Sprintf("\t\t%s: %s\n", key, val))
		}
	}

	return c.String(http.StatusOK, s.String())
}

func createCert(c echo.Context) error {
	domain := c.QueryParam("domain")
	ctx := c.Request().Context()

	caDir, err := acme_http.GetCADir(ctx, CADirURL)
	if err != nil {
		return fmt.Errorf("error in GetCADir: %w", err)
	}

	acctKid, pk, err := acme_http.CreateAccount(ctx, CAEmail, caDir, nil)
	if err != nil {
		return fmt.Errorf("error in CreateAccount: %w", err)
	}

	log.Println("account kid", acctKid)

	orderLocation, order, err := acme_http.CreateOrder(ctx, acctKid, domain, caDir, pk)
	if err != nil {
		return fmt.Errorf("error in CreateOrder: %w", err)
	}

	log.Printf("order response %+v\n", order)

	auth, err := acme_http.GetAuthorization(ctx, acctKid, pk, caDir, order)
	if err != nil {
		return fmt.Errorf("error in GetAuthorization: %w", err)
	}

	log.Printf("Authorization: %+v\n", *auth)

	challenge, err := acme_http.CreateChallenge(ctx, *auth, pk)
	if err != nil {
		return fmt.Errorf("error in CreateChallenge: %w", err)
	}

	log.Printf("Got challenge %+v\n", challenge)

	// Store the token for a key (we aren't bothering to match URL)
	httpChallenges.Store(challenge.Token, challenge.Key)
	log.Printf("Stored token %s key %s", challenge.Token, challenge.Key)

	chal, err := acme_http.NotifyChallenge(ctx, caDir, acctKid, pk, *challenge)
	if err != nil {
		return fmt.Errorf("error in NotifyChallenge: %w", err)
	}

	log.Printf("Got challenge response: %+v\n", chal)

	ct, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	err = acme_http.PollAuthorizationCompleted(ct, time.Second*2, order, acctKid, pk, caDir)
	if err != nil {
		return fmt.Errorf("error in PollAuthorizationCompleted: %w", err)
	}

	log.Println("auth completed")

	resource, err := acme_http.FinalizeOrder(ctx, acctKid, domain, orderLocation, pk, caDir, time.Second*2, order)
	if err != nil {
		return fmt.Errorf("error in FinalizeOrder: %w", err)
	}

	log.Printf("finalized order, getting cert")

	resource, err = acme_http.GetCert(ctx, *resource, acctKid, pk, caDir)
	if err != nil {
		return fmt.Errorf("error in GetCert: %w", err)
	}

	log.Printf("Got cert: %+v\n", resource)

	// Store cert on disk
	err = os.WriteFile(fmt.Sprintf("%s.issuer", domain), resource.IssuerCertificate, 0666)
	if err != nil {
		log.Fatalf("error writing issuer to disk: %s", err)
	}

	err = os.WriteFile(fmt.Sprintf("%s.key", domain), resource.PrivateKey, 0666)
	if err != nil {
		log.Fatalf("error writing key to disk: %s", err)
	}

	err = os.WriteFile(fmt.Sprintf("%s.cert", domain), resource.Certificate, 0666)
	if err != nil {
		log.Fatalf("error writing cert to disk: %s", err)
	}

	return c.String(http.StatusOK, "got cert")
}

func getCert(c echo.Context) error {
	domain := c.Param("domain")
	keyBytes, err := os.ReadFile(fmt.Sprintf("%s.key", domain))
	if os.IsNotExist(err) {
		return c.String(http.StatusNotFound, "tls key does not exist for "+domain)
	}
	if err != nil {
		return fmt.Errorf("error in os.Readfile for key: %w", err)
	}

	certBytes, err := os.ReadFile(fmt.Sprintf("%s.cert", domain))
	if os.IsNotExist(err) {
		return c.String(http.StatusNotFound, "tls cert does not exist for "+domain)
	}
	if err != nil {
		return fmt.Errorf("error in os.Readfile for cert: %w", err)
	}

	return c.JSON(http.StatusOK, struct {
		Cert string
		Key  string
	}{
		Cert: string(certBytes),
		Key:  string(keyBytes),
	})
}

func getConfig(c echo.Context) error {
	domain := c.Param("domain")

	routingBytes, err := os.ReadFile(fmt.Sprintf("%s.json", domain))
	if os.IsNotExist(err) {
		return c.String(http.StatusNotFound, "routing config does not exist for "+domain)
	}
	if err != nil {
		return fmt.Errorf("error in os.Readfile for routing config: %w", err)
	}

	return c.JSONBlob(http.StatusOK, routingBytes)
}

func getKey(c echo.Context) error {
	domain := c.Param("domain")
	token := c.Param("token")
	log.Println("getting token for domain", domain, "and token", token) // we don't care about the domain here, just logging to show we have it
	key, found := httpChallenges.LoadAndDelete(token)
	if !found {
		return c.String(http.StatusNotFound, "did not have that key!")
	}

	return c.JSON(http.StatusOK, struct {
		Key string
	}{
		Key: key,
	})
}

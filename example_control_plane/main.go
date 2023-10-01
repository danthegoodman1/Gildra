package main

import (
	"context"
	"examplecontrolplane/syncx"
	"fmt"
	"github.com/danthegoodman1/Gildra/acme_http"
	"github.com/labstack/echo/v4"
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
)

func main() {
	server := echo.New()
	server.HideBanner = true
	server.HidePort = true
	log.Println("starting example control plane on :8080")

	server.GET("/echo", echoHandler)
	server.POST("/create_cert", createCert)
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

	caDir, err := acme_http.GetCADir(ctx, "https://acme-staging-v02.api.letsencrypt.org/directory")
	if err != nil {
		return fmt.Errorf("error in GetCADir: %w", err)
	}

	acctKid, pk, err := acme_http.CreateAccount(ctx, os.Getenv("EMAIL"), caDir, nil)
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
	httpChallenges.Store(challenge.Key, challenge.Token)

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

	return c.String(http.StatusOK, "got cert")
}

func getCert(c echo.Context) error {

}

func getConfig(c echo.Context) error {

}

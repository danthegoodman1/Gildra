package acme

import (
	"log"
	"net/http"
	"strings"
)

type ACMEHTTPServer struct {
	Domain  string
	Token   string
	KeyAuth string
}

func (ahs *ACMEHTTPServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	log.Printf("GOT REQUEST: %s", req.URL.String())

	if strings.HasSuffix(req.URL.String(), ahs.Token) {
		// write `data` to response
		log.Printf("GOT REQUEST: Sending keyAuth for token %s", ahs.Token)
		res.Write([]byte(ahs.KeyAuth))
	} else {
		log.Println("GOT REQUEST: dont know what that was")
		res.Write([]byte("no"))
	}
}

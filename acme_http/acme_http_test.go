package acme_http

import (
	"context"
	"log"
	"os"
	"testing"
	"time"
)

func TestStagingLetsEncrypt(t *testing.T) {
	ctx := context.Background()
	caDir, err := GetCADir(ctx, "https://acme-staging-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatal(err)
	}

	//log.Println(spew.Sdump(p.caDir))

	acctKid, pk, err := CreateAccount(ctx, "deftesting@icloud.com", caDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	log.Println("account kid", acctKid)

	orderLocation, order, err := CreateOrder(ctx, acctKid, "getinsync.co", caDir, pk)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("order response %+v\n", order)

	auth, err := GetAuthorization(ctx, acctKid, pk, caDir, order)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Authorization: %+v\n", *auth)

	challenge, err := CreateChallenge(ctx, *auth, pk)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Got challenge %+v\n", challenge)

	chal, err := NotifyChallenge(ctx, caDir, acctKid, pk, *challenge)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Got challenge response: %+v\n", chal)

	ct, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	err = PollAuthorizationCompleted(ct, time.Second*2, order, acctKid, pk, caDir)
	if err != nil {
		t.Fatal(err)
	}

	log.Println("auth completed")

	resource, err := FinalizeOrder(ctx, acctKid, "getinsync.co", orderLocation, pk, caDir, time.Second*2, order)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("finalized order, getting cert")

	resource, err = GetCert(ctx, *resource, acctKid, pk, caDir)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Got cert: %+v\n", resource)
}

func TestZeroSSL(t *testing.T) {
	ctx := context.Background()
	caDir, err := GetCADir(ctx, "https://acme.zerossl.com/v2/DV90/directory")
	if err != nil {
		t.Fatal(err)
	}

	//log.Println(spew.Sdump(p.caDir))

	acctKid, pk, err := CreateAccount(ctx, "deftesting@icloud.com", caDir, &EABOptions{
		KID:     os.Getenv("ZEROSSL_KID"),
		HMACKey: os.Getenv("ZEROSSL_HMAC"),
	})
	if err != nil {
		t.Fatal(err)
	}

	log.Println("account kid", acctKid)

	orderLocation, order, err := CreateOrder(ctx, acctKid, "getinsync.co", caDir, pk)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("order response %+v\n", order)

	auth, err := GetAuthorization(ctx, acctKid, pk, caDir, order)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Authorization: %+v\n", *auth)

	challenge, err := CreateChallenge(ctx, *auth, pk)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Got challenge %+v\n", challenge)

	chal, err := NotifyChallenge(ctx, caDir, acctKid, pk, *challenge)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Got challenge response: %+v\n", chal)

	ct, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	err = PollAuthorizationCompleted(ct, time.Second*2, order, acctKid, pk, caDir)
	if err != nil {
		t.Fatal(err)
	}

	log.Println("auth completed")

	resource, err := FinalizeOrder(ctx, acctKid, "getinsync.co", orderLocation, pk, caDir, time.Second*2, order)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("finalized order, getting cert")

	resource, err = GetCert(ctx, *resource, acctKid, pk, caDir)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Got cert: %+v\n", resource)
}

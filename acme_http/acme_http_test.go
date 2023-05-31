package acme_http

import (
	"context"
	"testing"
)

func TestStagingLetsEncrypt(t *testing.T) {
	p, err := NewPipeline(context.Background(), "https://acme-staging-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(p.caDir)
}

func TestZeroSSL(t *testing.T) {
	p, err := NewPipeline(context.Background(), "https://acme.zerossl.com/v2/DV90/directory")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(p.caDir)
}

package acme_http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type (
	Pipeline struct {
		cADirURL string
		caDir    CADir
	}
)

var (
	ErrHighStatusCode = errors.New("high status code")
)

func NewPipeline(ctx context.Context, caDirURL string) (*Pipeline, error) {
	// Get the CA Directory
	p := &Pipeline{
		cADirURL: caDirURL,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", p.cADirURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error in http.NewRequestWithContext: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error in doing request: %w", err)
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading request body: %w", err)
	}
	if res.StatusCode > 299 {
		return nil, fmt.Errorf("status %d - body %s - %w", res.StatusCode, string(resBody), ErrHighStatusCode)
	}

	err = json.Unmarshal(resBody, &p.caDir)
	if err != nil {
		return nil, fmt.Errorf("error in unmarshaling CA dir: %w", err)
	}

	return p, nil
}

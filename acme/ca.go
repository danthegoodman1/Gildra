package acme

// Generated by https://quicktype.io

type CADir struct {
	EYRTEG7HSJw string `json:"EYRteG7hSJw"`
	KeyChange   string `json:"keyChange"`
	Meta        Meta   `json:"meta"`
	NewAccount  string `json:"newAccount"`
	NewNonce    string `json:"newNonce"`
	NewOrder    string `json:"newOrder"`
	RenewalInfo string `json:"renewalInfo"`
	RevokeCERT  string `json:"revokeCert"`
}

type Meta struct {
	CaaIdentities  []string `json:"caaIdentities"`
	TermsOfService string   `json:"termsOfService"`
	Website        string   `json:"website"`
}

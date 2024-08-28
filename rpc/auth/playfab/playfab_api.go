package playfab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type response struct {
	Code int `json:"code"`
	Data struct {
		AccountInfo accountInfo `json:"AccountInfo"`
	} `json:"data"`
}

type accountInfo struct {
	PlayFabID   string `json:"PlayFabId"`
	PrivateInfo struct {
		Email string `json:"Email"`
	} `json:"PrivateInfo"`
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func getAccountInfo(ctx context.Context, titleID string, sessionTicket string, client HTTPClient) (*accountInfo, error) {
	url := fmt.Sprintf("https://%s.playfabapi.com/Client/GetAccountInfo", titleID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authorization", sessionTicket)

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PlayFab error: %s", res.Status)
	}

	var resp response
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.Data.AccountInfo.PlayFabID == "" {
		return nil, fmt.Errorf("PlayFab account info not found")
	}

	return &resp.Data.AccountInfo, nil
}

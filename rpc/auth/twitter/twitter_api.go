package twitter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type userData struct {
	ID    string `json:"id"`
	Email string `json:"confirmed_email"`
}

type response struct {
	Data userData `json:"data"`
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func getUser(ctx context.Context, bearerToken string, client HTTPClient) (*userData, error) {
	url := "https://api.x.com/2/users/me?user.fields=confirmed_email"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("X error: %s", res.Status)
	}

	var resp response
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &resp.Data, nil
}

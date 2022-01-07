package traktdeviceauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

var ErrDeviceCodeUnclaimed error = errors.New("the user has not yet claimed the device code")
var ErrInvalidDeviceCode error = errors.New("invalid device code")
var ErrForbidden error = errors.New("invalid API key or unapproved application")
var ErrDeviceCodeAlreadyApproved error = errors.New("device code has already been approved")
var ErrDeviceCodeExpired error = errors.New("the device code has expired, please regenerate a new one")
var ErrDeviceCodeDenied error = errors.New("the device code was denied by the user")
var ErrPollRateTooFast error = errors.New("the API is being polled too quickly")
var ErrServerError error = errors.New("the Trakt API is reporting an internal problem, please check back later")
var ErrServiceOverloaded error = errors.New("the servers are overloaded, please try again in 30 seconds")
var ErrCloudflareError error = errors.New("there is an issue with Cloudflare")

// GenerateNewCode wraps GenerateNewCodeContext using context.Background().
func GenerateNewCode(clientID string) (CodeResponse, error) {
	return GenerateNewCodeContext(context.Background(), clientID)
}

// GenerateNewCodeContext reaches out to the Trakt API to acquire a claimable code.
func GenerateNewCodeContext(ctx context.Context, clientID string) (CodeResponse, error) {
	dataBuf := bytes.NewBufferString(fmt.Sprintf(`{"client_id": "%s"}`, clientID))

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.trakt.tv/oauth/device/code", dataBuf)
	if err != nil {
		return CodeResponse{}, fmt.Errorf("GenerateNewCode: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Trakt-API-Version", "2")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return CodeResponse{}, fmt.Errorf("GenerateNewCode: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200: // The code has been returned, continue on to the decode stage.
	case 403:
		return CodeResponse{}, ErrForbidden
	case 500:
		return CodeResponse{}, ErrServerError
	case 503, 504:
		return CodeResponse{}, ErrServiceOverloaded
	case 520, 521, 522:
		return CodeResponse{}, ErrCloudflareError
	default:
		return CodeResponse{}, fmt.Errorf("RequestToken: unexpected status code '%v'", resp.StatusCode)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return CodeResponse{}, fmt.Errorf("GenerateNewCode: %w", err)
	}

	codeResp := CodeResponse{}
	if err = json.Unmarshal(b, &codeResp); err != nil {
		return CodeResponse{}, fmt.Errorf("GenerateNewCode: %w", err)
	}

	return codeResp, nil
}

// PollForAuthToken wraps PollForAuthTokenContext using context.Background().
func PollForAuthToken(codeResp CodeResponse, clientID, clientSecret string) (TokenResponse, error) {
	return PollForAuthTokenContext(context.Background(), codeResp, clientID, clientSecret)
}

// PollForAuthTokenContext continuously polls for the access token from a CodeResponse.
// The passed context is truncated using context.WithDeadline to match the CodeResponse.ExpiresIn value.
func PollForAuthTokenContext(ctx context.Context, codeResp CodeResponse, clientID, clientSecret string) (TokenResponse, error) {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second*time.Duration(codeResp.ExpiresIn)))
	defer cancel()

	for {
		select {
		case <-time.After(time.Second * time.Duration(codeResp.Interval)):
			resp, err := RequestTokenContext(ctx, codeResp, clientID, clientSecret)
			if err != nil {
				return resp, nil
			}

			if !errors.Is(err, ErrDeviceCodeUnclaimed) {
				return TokenResponse{}, fmt.Errorf("PollForAuthToken: %w", err)
			}
		case <-ctx.Done():
			return TokenResponse{}, errors.New("PollForAuthToken: could not retrieve auth token, exceeded context")
		}
	}
}

// RequestToken wraps RequestTokenContext using context.Background().
func RequestToken(codeResp CodeResponse, clientID, clientSecret string) (TokenResponse, error) {
	return RequestTokenContext(context.Background(), codeResp, clientID, clientSecret)
}

// RequestTokenContext determines returns a TokenResponse if the provided code has been claimed by the user.
// If it has not, or there is another error, it will RequestTokenContext returns a customized error value
// which details the issue.
//
// This function is provided as a convenience, but it is recommended to use PollForAuthToken unless you have
// a very specific use case for this function.
func RequestTokenContext(ctx context.Context, codeResp CodeResponse, clientID, clientSecret string) (TokenResponse, error) {
	dataBuf := bytes.NewBufferString(fmt.Sprintf(`{"code": "%s", "client_id": "%s", "client_secret": "%s"}`, codeResp.DeviceCode, clientID, clientSecret))

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.trakt.tv/oauth/device/token", dataBuf)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("RequestToken: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Trakt-API-Version", "2")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("RequestToken: %w", err)
	}

	switch resp.StatusCode {
	case 200: // The access token has been returned, continue on to the decode stage.
	case 400:
		return TokenResponse{}, ErrDeviceCodeUnclaimed
	case 404:
		return TokenResponse{}, ErrInvalidDeviceCode
	case 409:
		return TokenResponse{}, ErrDeviceCodeAlreadyApproved
	case 410:
		return TokenResponse{}, ErrDeviceCodeExpired
	case 418:
		return TokenResponse{}, ErrDeviceCodeDenied
	case 429:
		return TokenResponse{}, ErrPollRateTooFast
	case 500:
		return TokenResponse{}, ErrServerError
	case 503, 504:
		return TokenResponse{}, ErrServiceOverloaded
	case 520, 521, 522:
		return TokenResponse{}, ErrCloudflareError
	default:
		return TokenResponse{}, fmt.Errorf("RequestToken: unexpected status code '%v'", resp.StatusCode)
	}

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close() // To avoid accumulating 1800 response bodies using defer, just close the body as soon as it's done being used.
	if err != nil {
		return TokenResponse{}, fmt.Errorf("RequestToken: %w", err)
	}

	respStruct := internalTokenResponse{}
	if err = json.Unmarshal(b, &respStruct); err != nil {
		return TokenResponse{}, fmt.Errorf("RequestToken: %w", err)
	}

	return transformInternalTokenResponse(respStruct), nil
}

// transformInternalTokenResponse takes an internalTokenResponse and turns it into
// a TokenResponse by copying the correct values and converting the time based values
// into time.Time structs.
func transformInternalTokenResponse(internal internalTokenResponse) (t TokenResponse) {
	t.AccessToken = internal.AccessToken
	t.TokenType = internal.TokenType
	t.RefreshToken = internal.RefreshToken
	t.Scope = internal.Scope
	t.CreatedAt = time.Unix(int64(internal.CreatedAt), 0)
	t.ExpiresAt = t.CreatedAt.Add(time.Second * time.Duration(internal.ExpiresIn))
	return
}

// CodeResponse is used to contain the results of GenerateNewCode.
// The user should be directed to VerificationURL and instructed to enter
// UserCode into the box presented.
// None of this data needs to persist between restarts.
type CodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"` // How long the code will last in seconds
	Interval        int    `json:"interval"`   // The interval in seconds that the application is allowed to poll at
}

// TokenResponse contains the results of RequestToken.
// This data should persist between restarts unless you want to
// prompt the user to authorize your app on every launch.
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresAt    time.Time
	RefreshToken string
	Scope        string
	CreatedAt    time.Time
}

// The internalTokenResponse struct directly maps to the output from the Trakt API.
// It gets converted to TokenResponse to be return to the user.
type internalTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	CreatedAt    int    `json:"created_at"` // The seconds since the epoch when the token was created (GMT).
}
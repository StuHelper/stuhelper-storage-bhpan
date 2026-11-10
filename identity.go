package bhpan

import "context"

// Identity contains only the stable provider account ID. Personal profile fields
// returned by the supplier are intentionally not retained or exposed.
type Identity struct {
	ID string `json:"id"`
}

func (c *Client) Identity(ctx context.Context) (Identity, error) {
	var out struct {
		Type   string `json:"type"`
		UserID string `json:"userid"`
	}
	err := c.api(ctx, "identity", "POST", "/api/eacp/v1/user/get", struct{}{}, &out)
	if err != nil {
		return Identity{}, err
	}
	if out.Type != "user" || !textOK(out.UserID) || len(out.UserID) > 256 {
		return Identity{}, ErrProtocol
	}
	return Identity{ID: out.UserID}, nil
}

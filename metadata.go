package bhpan

import (
	"context"
	"net/url"
	"regexp"
)

var objectIdentity = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type FileMetadata struct {
	ObjectID   string
	DocumentID string
	Name       string
	Revision   string
	Size       int64
	LibraryID  string
}

// FileInfo resolves a stable object ID even after its location changes into the
// recycle bin. A missing object remains distinct from an inaccessible object.
func (c *Client) FileInfo(ctx context.Context, id string) (FileMetadata, error) {
	if !objectIdentity.MatchString(id) {
		return FileMetadata{}, ErrInput
	}
	var out struct {
		ID         string `json:"object_id"`
		DocumentID string `json:"doc_id"`
		Name       string `json:"name"`
		Revision   string `json:"rev"`
		Size       *int64 `json:"size"`
		Type       string `json:"type"`
		Library    struct {
			ID string `json:"id"`
		} `json:"doc_lib"`
	}
	err := c.api(ctx, "file-info", "GET", "/api/efast/v2/items/"+url.PathEscape(id)+"/all", nil, &out)
	if err != nil {
		return FileMetadata{}, err
	}
	if out.ID != id || out.Type != "file" || !textOK(out.DocumentID) || !textOK(out.Name) || !textOK(out.Revision) || out.Size == nil || *out.Size < 0 || !textOK(out.Library.ID) {
		return FileMetadata{}, ErrProtocol
	}
	return FileMetadata{ObjectID: id, DocumentID: out.DocumentID, Name: out.Name, Revision: out.Revision, Size: *out.Size, LibraryID: out.Library.ID}, nil
}

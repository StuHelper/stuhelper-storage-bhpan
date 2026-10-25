package bhpan

import (
	"context"
	"encoding/hex"
	"io"
	"strings"
	"time"
)

func digestOK(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}

// FastUploadAvailable only reports the provider's preflight match. A true result
// is not evidence that a new file has been created.
func (c *Client) FastUploadAvailable(ctx context.Context, length int64, sliceMD5 string) (bool, error) {
	if length <= 0 || !digestOK(sliceMD5, 32) {
		return false, ErrInput
	}
	var out struct {
		Match *bool `json:"match"`
	}
	err := c.api(ctx, "fast-upload-check", "POST", "/api/efast/v1/file/predupload", map[string]any{"length": length, "slice_md5": strings.ToLower(sliceMD5)}, &out)
	if err != nil {
		return false, err
	}
	if out.Match == nil {
		return false, ErrProtocol
	}
	return *out.Match, nil
}
func (c *Client) FastUpload(ctx context.Context, parent, name string, length int64, md5, crc32 string) error {
	if !textOK(parent) || !nameOK(name) || length <= 0 || !digestOK(md5, 32) || !digestOK(crc32, 8) {
		return ErrInput
	}
	var out struct {
		Success *bool `json:"success"`
	}
	err := c.api(ctx, "fast-upload", "POST", "/api/efast/v1/file/dupload", map[string]any{"client_mtime": time.Now().UnixMilli(), "docid": parent, "name": name, "length": length, "md5": strings.ToLower(md5), "crc32": strings.ToLower(crc32), "ondup": 1}, &out)
	if err != nil {
		return err
	}
	if out.Success == nil {
		return ErrProtocol
	}
	if !*out.Success {
		return ErrRejected
	}
	return nil
}
func (c *Client) DownloadArchive(ctx context.Context, name string, directories, files []string, dst io.Writer) (int64, error) {
	if !nameOK(name) || len(directories)+len(files) == 0 || dst == nil {
		return 0, ErrInput
	}
	for _, ids := range [][]string{directories, files} {
		for _, id := range ids {
			if !textOK(id) {
				return 0, ErrInput
			}
		}
	}
	if directories == nil {
		directories = []string{}
	}
	if files == nil {
		files = []string{}
	}
	var out struct {
		URL string `json:"url"`
	}
	err := c.api(ctx, "download-archive", "POST", "/api/efast/v1/file/batchdownload", map[string]any{"name": name + ".zip", "reqhost": strings.TrimPrefix(c.cloud, "https://"), "dirs": directories, "files": files}, &out)
	if err != nil {
		return 0, err
	}
	g, err := c.decodeGrant([]string{"GET", out.URL}, "GET")
	if err != nil {
		return 0, err
	}
	resp, err := c.data(ctx, g, nil, 0)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(dst, resp.Body)
	if err != nil {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		return n, &Error{"archive-body", resp.StatusCode, ErrUnavailable}
	}
	return n, nil
}
func (c *Client) ShareHistory(ctx context.Context) ([]Share, error) {
	var out struct {
		Entries []struct {
			Document ShareItem `json:"doc"`
			Links    []struct {
				ID       string   `json:"id"`
				Title    string   `json:"title"`
				Expires  string   `json:"expires_at"`
				Password string   `json:"password"`
				Limit    int64    `json:"limited_times"`
				Allow    []string `json:"allow"`
			} `json:"link_configs"`
		} `json:"entries"`
	}
	if err := c.api(ctx, "share-history", "GET", "/api/doc-share/v1/docs-shared-with-anyone", nil, &out); err != nil {
		return nil, err
	}
	if out.Entries == nil {
		return nil, ErrProtocol
	}
	shares := []Share{}
	for _, entry := range out.Entries {
		for _, link := range entry.Links {
			if !textOK(link.ID) || !textOK(entry.Document.ID) {
				return nil, ErrProtocol
			}
			item := entry.Document
			item.Allow = link.Allow
			shares = append(shares, Share{ID: link.ID, Title: link.Title, ExpiresAt: link.Expires, Password: link.Password, LimitedTimes: link.Limit, Item: item})
		}
	}
	return shares, nil
}

// SharedDirectory retains the same share authority on each returned child.
type SharedDirectory struct{ Directories, Files []SharedEntry }

func (c *Client) ListShared(ctx context.Context, entry SharedEntry) (SharedDirectory, error) {
	if !textOK(entry.token) || !textOK(entry.ID) || entry.Size != -1 {
		return SharedDirectory{}, ErrInput
	}
	var out Directory
	err := c.json(ctx, c.anonymousClient(), entry.token, "share-list", "POST", "/api/efast/v1/dir/list", map[string]any{"docid": entry.ID, "by": "name", "sort": "asc"}, &out)
	if err != nil {
		return SharedDirectory{}, err
	}
	result := SharedDirectory{Directories: []SharedEntry{}, Files: []SharedEntry{}}
	for _, item := range out.Directories {
		result.Directories = append(result.Directories, SharedEntry{ID: item.ID, Name: item.Name, Size: -1, token: entry.token})
	}
	for _, item := range out.Files {
		result.Files = append(result.Files, SharedEntry{ID: item.ID, Name: item.Name, Size: item.Size, token: entry.token})
	}
	return result, nil
}

package bhpan

import (
	"context"
	"encoding/json"
)

type Library struct {
	Type     string `json:"type,omitempty"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision string `json:"rev"`
}
type Quota struct {
	Allocated int64 `json:"allocated"`
	Used      int64 `json:"used"`
}

func (q Quota) Available() int64 {
	if q.Used > q.Allocated {
		return 0
	}
	return q.Allocated - q.Used
}

type Entry struct {
	Revision     string `json:"rev,omitempty"`
	OriginalPath string `json:"path,omitempty"`
	ID           string `json:"docid"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	Created      int64  `json:"create_time"`
	Modified     int64  `json:"modified"`
}
type Directory struct {
	Directories []Entry `json:"dirs"`
	Files       []Entry `json:"files"`
}
type Size struct {
	Bytes       int64 `json:"totalsize"`
	Files       int64 `json:"filenum"`
	Directories int64 `json:"dirnum"`
}

func (c *Client) Libraries(ctx context.Context) ([]Library, error) {
	var out []Library
	err := c.api(ctx, "libraries", "GET", "/api/efast/v1/owned-doc-lib", nil, &out)
	if err == nil {
		for _, e := range out {
			if !textOK(e.ID) {
				return nil, ErrProtocol
			}
		}
	}
	return out, err
}
func (c *Client) Quota(ctx context.Context) (Quota, error) {
	var out struct {
		Allocated *int64 `json:"allocated"`
		Used      *int64 `json:"used"`
	}
	err := c.api(ctx, "quota", "GET", "/api/efast/v1/quota/user", nil, &out)
	if err != nil {
		return Quota{}, err
	}
	if out.Allocated == nil || out.Used == nil || *out.Allocated < 0 || *out.Used < 0 {
		return Quota{}, ErrProtocol
	}
	// An account may be over quota after the provider reduces its allocation.
	return Quota{*out.Allocated, *out.Used}, nil
}
func (c *Client) List(ctx context.Context, id string) (Directory, error) {
	var out Directory
	if !textOK(id) {
		return out, ErrInput
	}
	err := c.api(ctx, "list", "POST", "/api/efast/v1/dir/list", map[string]any{"docid": id, "by": "name", "sort": "asc"}, &out)
	if err == nil {
		for _, items := range [][]Entry{out.Directories, out.Files} {
			for _, v := range items {
				if !textOK(v.ID) || !textOK(v.Name) || v.Size < -1 {
					return Directory{}, ErrProtocol
				}
			}
		}
	}
	return out, err
}
func (c *Client) DirectorySize(ctx context.Context, id string) (Size, error) {
	var out Size
	if !textOK(id) {
		return out, ErrInput
	}
	err := c.api(ctx, "size", "POST", "/api/efast/v1/dir/size", map[string]any{"docid": id, "onlyrecycle": false}, &out)
	if err == nil && (out.Bytes < 0 || out.Files < 0 || out.Directories < 0) {
		err = ErrProtocol
	}
	return out, err
}
func (c *Client) SuggestedName(ctx context.Context, id, name string) (string, error) {
	if !textOK(id) || !nameOK(name) {
		return "", ErrInput
	}
	var out struct {
		Name string `json:"name"`
	}
	err := c.api(ctx, "suggest-name", "POST", "/api/efast/v1/file/getsuggestname", map[string]any{"docid": id, "name": name}, &out)
	if err == nil && !nameOK(out.Name) {
		err = ErrProtocol
	}
	return out.Name, err
}
func (c *Client) change(ctx context.Context, op, path string, in map[string]any, wantID bool) (string, error) {
	for _, v := range in {
		if s, ok := v.(string); ok && !textOK(s) {
			return "", ErrInput
		}
	}
	var out struct {
		ID string `json:"docid"`
	}
	var target any
	if wantID {
		target = &out
	}
	err := c.api(ctx, op, "POST", "/api/efast/v1/"+path, in, target)
	if err == nil && wantID && !textOK(out.ID) {
		err = ErrProtocol
	}
	return out.ID, err
}
func (c *Client) CreateDirectory(ctx context.Context, parent, name string) (string, error) {
	if !nameOK(name) {
		return "", ErrInput
	}
	return c.change(ctx, "mkdir", "dir/create", map[string]any{"docid": parent, "name": name, "ondup": 1}, true)
}
func (c *Client) Rename(ctx context.Context, id, name string) error {
	if !nameOK(name) {
		return ErrInput
	}
	_, err := c.change(ctx, "rename", "dir/rename", map[string]any{"docid": id, "name": name, "ondup": 1}, false)
	return err
}
func (c *Client) Move(ctx context.Context, id, parent string) (string, error) {
	return c.change(ctx, "move", "dir/move", map[string]any{"docid": id, "destparent": parent, "ondup": 1}, true)
}
func (c *Client) Copy(ctx context.Context, id, parent string) (string, error) {
	return c.change(ctx, "copy", "dir/copy", map[string]any{"docid": id, "destparent": parent, "ondup": 1}, true)
}
func (c *Client) Delete(ctx context.Context, id string) error {
	_, err := c.change(ctx, "delete", "file/delete", map[string]any{"docid": id}, false)
	return err
}
func (c *Client) Restore(ctx context.Context, id string) (string, error) {
	return c.change(ctx, "restore", "recycle/restore", map[string]any{"docid": id, "ondup": 1}, true)
}
func (c *Client) Purge(ctx context.Context, id string) error {
	_, err := c.change(ctx, "purge", "recycle/delete", map[string]any{"docid": id}, false)
	return err
}

// RecycleBin returns one explicit page, so callers cannot mistake the first 100
// entries for a complete account inventory.
func (c *Client) RecycleBin(ctx context.Context, root string, start, limit int) (Directory, error) {
	var out Directory
	if !textOK(root) || start < 0 || limit < 1 || limit > 1000 {
		return out, ErrInput
	}
	err := c.api(ctx, "recycle-list", "POST", "/api/efast/v1/recycle/list", map[string]any{"docid": root, "by": "time", "sort": "desc", "start": start, "limit": limit}, &out)
	return out, err
}

// Required wire fields distinguish an empty directory from an invalid response.
func (d *Directory) UnmarshalJSON(data []byte) error {
	type wire Directory
	var out wire
	if json.Unmarshal(data, &out) != nil || out.Directories == nil || out.Files == nil {
		return ErrProtocol
	}
	*d = Directory(out)
	return nil
}
func (e *Entry) UnmarshalJSON(data []byte) error {
	type wire Entry
	var out wire
	var required struct {
		Size *int64 `json:"size"`
	}
	if json.Unmarshal(data, &out) != nil || json.Unmarshal(data, &required) != nil || required.Size == nil || !textOK(out.ID) || !textOK(out.Name) || out.Size < -1 {
		return ErrProtocol
	}
	*e = Entry(out)
	return nil
}
func (s *Size) UnmarshalJSON(data []byte) error {
	var out struct {
		Bytes       *int64 `json:"totalsize"`
		Files       *int64 `json:"filenum"`
		Directories *int64 `json:"dirnum"`
	}
	if json.Unmarshal(data, &out) != nil || out.Bytes == nil || out.Files == nil || out.Directories == nil || *out.Bytes < 0 || *out.Files < 0 || *out.Directories < 0 {
		return ErrProtocol
	}
	*s = Size{*out.Bytes, *out.Files, *out.Directories}
	return nil
}

// bhpan-probe reads credentials from stdin and emits aggregate results only.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/StuHelper/stuhelper-storage-bhpan"
)

type account struct{ Username, Password, Mode string }
type input struct {
	Accounts                 []account
	Files, Multipart, Shares bool
}

func main() {
	var in input
	if json.NewDecoder(io.LimitReader(os.Stdin, 8192)).Decode(&in) != nil || len(in.Accounts) == 0 || len(in.Accounts) > 2 {
		fmt.Fprintln(os.Stderr, "invalid stdin input")
		os.Exit(1)
	}
	for _, a := range in.Accounts {
		if a.Mode != "" && a.Mode != "sso" && a.Mode != "local" {
			fmt.Fprintln(os.Stderr, "invalid authentication mode")
			os.Exit(1)
		}
	}
	failed := false
	for i := range in.Accounts {
		a := in.Accounts[i]
		in.Accounts[i] = account{}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		c, err := bhpan.New(bhpan.Config{Timeout: 60 * time.Second})
		if err == nil {
			if a.Mode == "local" {
				err = c.LoginLocal(ctx, a.Username, a.Password)
			} else {
				err = c.Login(ctx, a.Username, a.Password)
			}
		}
		a = account{}
		result := map[string]any{"account": i + 1, "login": err == nil}
		if err == nil {
			var libs []bhpan.Library
			libs, err = c.Libraries(ctx)
			if err == nil {
				result["libraries"] = len(libs)
			}
			if err == nil {
				q, e := c.Quota(ctx)
				err = e
				if e == nil {
					result["quota_valid"] = q.Allocated >= 0 && q.Used >= 0
				}
			}
			if err == nil && len(libs) > 0 {
				_, err = c.List(ctx, libs[0].ID)
				if err == nil {
					result["root_list_valid"] = true
				}
			}
			if err == nil && in.Files && len(libs) > 0 {
				err = files(ctx, c, libs[0].ID, in, result)
			}
		}
		if err != nil {
			result["error"] = err.Error()
			failed = true
		}
		if c != nil {
			c.Close()
		}
		cancel()
		_ = json.NewEncoder(os.Stdout).Encode(result)
	}
	if failed {
		os.Exit(1)
	}
}

func files(ctx context.Context, c *bhpan.Client, root string, in input, result map[string]any) (err error) {
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return errors.New("probe: random source unavailable")
	}
	name := "stuhelper-next-bhpan-test-" + hex.EncodeToString(nonce)
	dir, err := c.CreateDirectory(ctx, root, name)
	if err != nil {
		return err
	}
	result["temporary_directory_created"] = true
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		e := c.Delete(cleanCtx, dir)
		if e == nil {
			var recycleID string
			recycleID, e = recycled(cleanCtx, c, root, name)
			if e == nil {
				e = c.Purge(cleanCtx, recycleID)
			}
		}
		result["temporary_directory_removed"] = e == nil
		if e != nil {
			err = errors.Join(err, fmt.Errorf("probe cleanup: %w", e))
		}
	}()
	payload := append([]byte("StuHelper Next BHpan adapter verification\n"), nonce...)
	upload, err := c.BeginUpload(ctx, dir, "probe.bin", int64(len(payload)))
	if err != nil {
		return err
	}
	if _, err = c.WriteUpload(ctx, upload, bytes.NewReader(payload)); err != nil {
		return err
	}
	if err = c.FinishUpload(ctx, upload.DocumentID, upload.Revision); err != nil {
		return err
	}
	if err = verifyDownload(ctx, c, upload.DocumentID, payload); err != nil {
		return err
	}
	result["upload_download_checksum"] = true
	if _, err = c.DirectorySize(ctx, dir); err != nil {
		return err
	}
	if _, err = c.SuggestedName(ctx, dir, "probe.bin"); err != nil {
		return err
	}
	if err = c.Rename(ctx, upload.DocumentID, "renamed.bin"); err != nil {
		return err
	}
	nested, err := c.CreateDirectory(ctx, dir, "nested")
	if err != nil {
		return err
	}
	copied, err := c.Copy(ctx, upload.DocumentID, nested)
	if err != nil {
		return err
	}
	if err = c.Rename(ctx, copied, "copied-"+hex.EncodeToString(nonce)+".bin"); err != nil {
		return err
	}
	moved, err := c.Move(ctx, copied, dir)
	if err != nil {
		return err
	}
	recycleName := "restore-" + hex.EncodeToString(nonce) + ".bin"
	if err = c.Rename(ctx, moved, recycleName); err != nil {
		return err
	}
	if err = c.Delete(ctx, moved); err != nil {
		return err
	}
	if _, err = c.RecycleBin(ctx, root, 0, 100); err != nil {
		return err
	}
	recycleID, err := recycled(ctx, c, root, recycleName)
	if err != nil {
		return err
	}
	restored, err := c.Restore(ctx, recycleID)
	if err != nil {
		return err
	}
	if err = verifyDownload(ctx, c, restored, payload); err != nil {
		return err
	}
	if err = c.Delete(ctx, restored); err != nil {
		return err
	}
	recycleID, err = recycled(ctx, c, root, recycleName)
	if err != nil {
		return err
	}
	if err = c.Purge(ctx, recycleID); err != nil {
		return err
	}
	result["file_lifecycle"] = true
	if in.Multipart {
		if err = multi(ctx, c, dir, nonce); err != nil {
			return err
		}
		result["multipart_checksum"] = true
	}
	if in.Shares {
		if err = share(ctx, c, upload.DocumentID, payload); err != nil {
			return err
		}
		result["protected_share_checksum"] = true
	}
	return nil
}
func verifyDownload(ctx context.Context, c *bhpan.Client, id string, want []byte) error {
	h := sha256.New()
	n, e := c.Download(ctx, id, h)
	if e != nil {
		return e
	}
	digest := sha256.Sum256(want)
	if n != int64(len(want)) || !bytes.Equal(h.Sum(nil), digest[:]) {
		return errors.New("probe: download checksum mismatch")
	}
	return nil
}
func multi(ctx context.Context, c *bhpan.Client, dir string, nonce []byte) error {
	limits, err := c.MultipartOptions(ctx)
	if err != nil {
		return err
	}
	if limits.MinimumSize > 32<<20 || limits.MaximumParts < 2 {
		return errors.New("probe: multipart limits exceed test budget")
	}
	payload := bytes.Repeat([]byte{0x63}, int(limits.MinimumSize)+len(nonce))
	copy(payload[len(payload)-len(nonce):], nonce)
	u, err := c.BeginMultipart(ctx, dir, "multipart.bin", int64(len(payload)))
	if err != nil {
		return err
	}
	grants, err := c.PartGrants(ctx, u, 1, 2)
	if err != nil {
		return err
	}
	var parts []bhpan.Part
	for i, chunk := range [][]byte{payload[:limits.MinimumSize], payload[limits.MinimumSize:]} {
		p, e := c.WritePart(ctx, grants[i], bytes.NewReader(chunk), int64(len(chunk)))
		if e != nil {
			return e
		}
		parts = append(parts, p)
	}
	if err = c.CompleteMultipart(ctx, u, parts); err != nil {
		return err
	}
	return verifyDownload(ctx, c, u.DocumentID, payload)
}
func share(ctx context.Context, c *bhpan.Client, id string, payload []byte) (err error) {
	nonce := make([]byte, 4)
	if _, err = rand.Read(nonce); err != nil {
		return errors.New("probe: random source unavailable")
	}
	s, err := c.CreateShare(ctx, bhpan.Share{Title: "Adapter verification", Password: hex.EncodeToString(nonce), ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), LimitedTimes: -1, Item: bhpan.ShareItem{ID: id, Type: "file", Allow: []string{"display", "preview", "download"}}})
	if err != nil {
		return err
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if e := c.DeleteShare(cleanCtx, s.ID); e != nil {
			err = errors.Join(err, e)
		}
	}()
	s.Title = "Adapter verification updated"
	if err = c.UpdateShare(ctx, s); err != nil {
		return err
	}
	if _, err = c.Shares(ctx, id); err != nil {
		return err
	}
	anonymous, err := bhpan.New(bhpan.Config{Timeout: 60 * time.Second})
	if err != nil {
		return err
	}
	defer anonymous.Close()
	entry, err := anonymous.ResolveShare(ctx, s.ID, s.Password)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := anonymous.DownloadShared(ctx, entry, h)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if n != int64(len(payload)) || !bytes.Equal(h.Sum(nil), digest[:]) {
		return errors.New("probe: share checksum mismatch")
	}
	return nil
}

func recycled(ctx context.Context, c *bhpan.Client, root, name string) (string, error) {
	for start := 0; start < 10000; start += 100 {
		d, e := c.RecycleBin(ctx, root, start, 100)
		if e != nil {
			return "", e
		}
		var found string
		for _, entries := range [][]bhpan.Entry{d.Directories, d.Files} {
			for _, item := range entries {
				if item.Name == name {
					if found != "" {
						return "", errors.New("probe: ambiguous recycle entry")
					}
					found = item.ID
				}
			}
		}
		if found != "" {
			return found, nil
		}
		if len(d.Files)+len(d.Directories) < 100 {
			break
		}
	}
	return "", errors.New("probe: created entry absent from recycle bin")
}

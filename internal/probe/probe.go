// Package probe implements the credential-redacting live verification workflow
// used by cmd/bhpan-probe and exercises it against local TLS fixtures in tests.
package probe

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"time"

	"github.com/StuHelper/stuhelper-storage-bhpan"
)

type Account struct {
	Username string
	Password string
	Mode     string
}

type Input struct {
	Accounts        []Account
	Files           bool
	Multipart       bool
	Shares          bool
	FastUpload      bool
	Archive         bool
	SharedDirectory bool
}

var (
	ErrInvalidInput = errors.New("invalid stdin input")
	ErrInvalidMode  = errors.New("invalid authentication mode")
	ErrProbeFailed  = errors.New("probe verification failed")
)

func Run(parentCtx context.Context, cfg bhpan.Config, stdin io.Reader, stdout io.Writer) error {
	var in Input
	if stdin == nil || stdout == nil || json.NewDecoder(io.LimitReader(stdin, 8192)).Decode(&in) != nil || len(in.Accounts) == 0 || len(in.Accounts) > 2 {
		return ErrInvalidInput
	}
	for _, a := range in.Accounts {
		if a.Mode != "" && a.Mode != "sso" && a.Mode != "local" {
			return ErrInvalidMode
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	failed := false
	for i := range in.Accounts {
		a := in.Accounts[i]
		in.Accounts[i] = Account{}
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Minute)
		result, accountFailed := probeAccount(ctx, cfg, i+1, a, in)
		if accountFailed {
			failed = true
		}
		cancel()
		_ = json.NewEncoder(stdout).Encode(result)
	}
	if failed {
		return ErrProbeFailed
	}
	return nil
}

func selectPersonalLibrary(libs []bhpan.Library) (string, error) {
	personal := ""
	for _, lib := range libs {
		if lib.Type == "user_doc_lib" {
			if personal != "" {
				return "", errors.New("probe: ambiguous personal libraries")
			}
			personal = lib.ID
		}
	}
	if personal == "" {
		return "", errors.New("probe: personal library not found")
	}
	return personal, nil
}

func probeAccount(ctx context.Context, cfg bhpan.Config, index int, a Account, in Input) (map[string]any, bool) {
	c, err := bhpan.New(cfg)
	if err == nil {
		if a.Mode == "local" {
			err = c.LoginLocal(ctx, a.Username, a.Password)
		} else {
			err = c.Login(ctx, a.Username, a.Password)
		}
	}
	a = Account{}
	result := map[string]any{"account": index, "login": err == nil}
	if err == nil {
		identity, e := c.Identity(ctx)
		err = e
		result["identity_valid"] = e == nil && identity.ID != ""
	}
	if err == nil {
		var libs []bhpan.Library
		var personalID string
		libs, err = c.Libraries(ctx)
		if err == nil {
			result["libraries"] = len(libs)
			personalID, err = selectPersonalLibrary(libs)
			if err == nil {
				result["personal_library_type"] = true
			}
		}
		if err == nil {
			q, e := c.Quota(ctx)
			err = e
			if e == nil {
				result["quota_valid"] = q.Allocated >= 0 && q.Used >= 0
			}
		}
		if err == nil {
			_, err = c.List(ctx, personalID)
			if err == nil {
				result["root_list_valid"] = true
			}
		}
		if err == nil && in.Files {
			err = files(ctx, cfg, c, personalID, in, result)
		}
	}
	failed := false
	if err != nil {
		result["error"] = err.Error()
		failed = true
	}
	if c != nil {
		c.Close()
	}
	return result, failed
}

func files(ctx context.Context, cfg bhpan.Config, c *bhpan.Client, root string, in Input, result map[string]any) (err error) {
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
	stableID := moved[strings.LastIndex(moved, "/")+1:]
	metadata, err := c.FileInfo(ctx, stableID)
	if err != nil {
		return err
	}
	if metadata.DocumentID != recycleID {
		return errors.New("probe: recycle identity mismatch")
	}
	result["recycle_object_id_preserved"] = true
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
	if _, err = c.FileInfo(ctx, stableID); !errors.Is(err, bhpan.ErrNotFound) {
		return errors.New("probe: permanent absence not verified")
	}
	result["permanent_absence_verified"] = true
	result["file_lifecycle"] = true
	if in.FastUpload {
		if err = fastUpload(ctx, c, dir, payload, result); err != nil {
			return err
		}
	}
	if in.Archive {
		if err = archive(ctx, c, nested, upload.DocumentID); err != nil {
			return err
		}
		result["archive_download_valid"] = true
	}
	if in.Multipart {
		if err = multi(ctx, c, dir, nonce); err != nil {
			return err
		}
		result["multipart_checksum"] = true
	}
	if in.Shares {
		if err = share(ctx, cfg, c, upload.DocumentID, payload); err != nil {
			return err
		}
		result["protected_share_checksum"] = true
		result["share_history_valid"] = true
	}
	if in.SharedDirectory {
		if err = sharedDirectory(ctx, cfg, c, nested, payload); err != nil {
			return err
		}
		result["shared_directory_checksum"] = true
	}
	return nil
}

func fastUpload(ctx context.Context, c *bhpan.Client, dir string, payload []byte, result map[string]any) error {
	md5Sum := md5.Sum(payload)
	md5Hex := hex.EncodeToString(md5Sum[:])
	crcHex := fmt.Sprintf("%08x", crc32.ChecksumIEEE(payload))
	match, err := c.FastUploadAvailable(ctx, int64(len(payload)), md5Hex)
	if err != nil {
		return err
	}
	result["fast_upload_preflight"] = match
	if !match {
		return nil
	}
	if err := c.FastUpload(ctx, dir, "fast-probe.bin", int64(len(payload)), md5Hex, crcHex); err != nil {
		return err
	}
	result["fast_upload_created"] = true
	return nil
}

func archive(ctx context.Context, c *bhpan.Client, dirID, fileID string) error {
	var dst bytes.Buffer
	n, err := c.DownloadArchive(ctx, "probe-archive", []string{dirID}, []string{fileID}, &dst)
	if err != nil {
		return err
	}
	if n <= 0 || int64(dst.Len()) != n {
		return errors.New("probe: empty or mismatched archive stream")
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

func share(ctx context.Context, cfg bhpan.Config, c *bhpan.Client, id string, payload []byte) (err error) {
	nonce := make([]byte, 4)
	if _, err = rand.Read(nonce); err != nil {
		return errors.New("probe: random source unavailable")
	}
	password := hex.EncodeToString(nonce)
	s, err := c.CreateShare(ctx, bhpan.Share{Title: "Adapter verification", Password: password, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), LimitedTimes: -1, Item: bhpan.ShareItem{ID: id, Type: "file", Allow: []string{"display", "preview", "download"}}})
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
	s.Password = password
	if err = c.UpdateShare(ctx, s); err != nil {
		return err
	}
	if _, err = c.Shares(ctx, id); err != nil {
		return err
	}
	if _, err = c.ShareHistory(ctx); err != nil {
		return err
	}
	anonymous, err := bhpan.New(cfg)
	if err != nil {
		return err
	}
	defer anonymous.Close()
	entry, err := anonymous.ResolveShare(ctx, s.ID, password)
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

func sharedDirectory(ctx context.Context, cfg bhpan.Config, c *bhpan.Client, folderID string, payload []byte) (err error) {
	up, err := c.BeginUpload(ctx, folderID, "nested-shared.bin", int64(len(payload)))
	if err != nil {
		return err
	}
	if _, err = c.WriteUpload(ctx, up, bytes.NewReader(payload)); err != nil {
		return err
	}
	if err = c.FinishUpload(ctx, up.DocumentID, up.Revision); err != nil {
		return err
	}
	nonce := make([]byte, 4)
	if _, err = rand.Read(nonce); err != nil {
		return errors.New("probe: random source unavailable")
	}
	password := hex.EncodeToString(nonce)
	s, err := c.CreateShare(ctx, bhpan.Share{Title: "Folder verification", Password: password, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), LimitedTimes: -1, Item: bhpan.ShareItem{ID: folderID, Type: "folder", Allow: []string{"display", "preview", "download"}}})
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
	anonymous, err := bhpan.New(cfg)
	if err != nil {
		return err
	}
	defer anonymous.Close()
	folderEntry, err := anonymous.ResolveShare(ctx, s.ID, password)
	if err != nil {
		return err
	}
	listing, err := anonymous.ListShared(ctx, folderEntry)
	if err != nil {
		return err
	}
	if len(listing.Files) == 0 {
		return errors.New("probe: shared folder listing empty")
	}
	h := sha256.New()
	n, err := anonymous.DownloadShared(ctx, listing.Files[0], h)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if n != int64(len(payload)) || !bytes.Equal(h.Sum(nil), digest[:]) {
		return errors.New("probe: shared folder file checksum mismatch")
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

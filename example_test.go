package bhpan_test

import (
	"testing"

	"github.com/StuHelper/stuhelper-storage-bhpan"
)

// This external package verifies that consumers can import the independent
// module without any campus-adapters, backend, or platform setup.
func TestIndependentImport(t *testing.T) {
	client, err := bhpan.New(bhpan.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
}

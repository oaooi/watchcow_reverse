package cgi

import "testing"

func TestChildCannotAccessAdminOrOtherApps(t *testing.T) {
	for _, path := range []string{"/", "/reverse", "/containers", "/containers/id", "/proxy/other/_", "/redirect/other/_", "/proxy/watchcow.emby/../../reverse", "/proxy/watchcow.emby//_"} {
		if Allowed("watchcow.emby", path, "GET") {
			t.Fatal("child escaped scope", path)
		}
	}
	if Allowed("watchcow.emby", "/proxy/watchcow.emby/_", "POST") {
		t.Fatal("child may not mutate admin state")
	}
	for _, path := range []string{"/proxy/watchcow.emby/_", "/redirect/watchcow.emby/admin/file.txt"} {
		if !Allowed("watchcow.emby", path, "GET") {
			t.Fatal("legitimate launch blocked", path)
		}
	}
	if Allowed("", "/containers", "GET") {
		t.Fatal("unscoped CGI allowed admin access")
	}
	if !Allowed("watchcow-r", "/reverse", "POST") {
		t.Fatal("admin scope blocked")
	}
}

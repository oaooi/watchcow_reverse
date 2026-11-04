package web

import "embed"

//go:embed css/*.css templates/*.tmpl js/*.js images/*.png
var Assets embed.FS

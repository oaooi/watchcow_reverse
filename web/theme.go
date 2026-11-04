package web

import _ "embed"

// ThemeCSS and ThemeJS are shared by both embedded control pages.
//
//go:embed css/theme.css
var ThemeCSS string

//go:embed js/theme.js
var ThemeJS string

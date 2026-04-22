package main

import (
	"fmt"
	"html"

	"github.com/pilcrowonpaper/go-json"

	_ "embed"
)

//go:embed frontend_assets/base.css
var baseStylesheet string

//go:embed frontend_assets/base.js
var baseScript string

func createPageHTML(requestId string, title string, bodyHTML string, script string, stylesheet string, dataJSON string) string {
	htmlTemplate := `<html lang="en">
<head>
	<title>%s</title>
	<meta name="description" content="An example website that implements email code sign-in and passkeys following best practices." />

	<meta charset="utf-8" />
    <meta name="viewport" content="width=device-width" />

	<meta property="og:title" content="%s" />
	<meta property="og:type" content="website" />
	<meta property="og:locale" content="en_US" />
	<meta property="og:site_name" content="Passwordless auth example" />
	<meta property="og:description" content="An example website that implements email code sign-in and passkeys following best practices." />
	<meta property="og:url" content="https://github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com" />
	<meta property="og:image" content="https://pilcrowonpaper.com/pilcrow.jpeg" />

	<meta name="twitter:card" content="summary">
    <meta name="twitter:site" content="@pilcrowonpaper">

	<link rel="icon" type="image/jpeg" href="https://pilcrowonpaper.com/pilcrow.jpeg">

	<style>%s</style>
	<style>%s</style>
</head>

<body>
	<header>
		<a id="home-link" href="/">Passwordless auth example</a>
	</header>
	<main>%s</main>
	<footer>
		<p>Created by <a href="https://pilcrowonpaper.com">pilcrow</a></p>
		<p>Questions and support: <a href="mailto:examples@auth.pilcrowonpaper.com">examples@auth.pilcrowonpaper.com</a></p>
		<p>Request ID: %s</p>
	</footer>
</body>
<script type="module">%s</script>
<script id="data" type="application/json">%s</script>
<script type="module">%s</script>
</html>`

	pageHTML := fmt.Sprintf(
		htmlTemplate,
		html.EscapeString(title),
		html.EscapeString(title),
		baseStylesheet,
		stylesheet,
		bodyHTML,
		html.EscapeString(requestId),
		script,
		dataJSON,
		baseScript,
	)

	return pageHTML
}

var htmlSafeJSONStringCharacterEscapingBehavior json.StringCharacterEscapingBehaviorInterface = htmlSafeJSONStringCharacterEscapingBehaviorStruct{}

type htmlSafeJSONStringCharacterEscapingBehaviorStruct struct{}

func (htmlSafeJSONStringCharacterEscapingBehaviorStruct) UseCharacter(r rune) bool {
	return r != '<' && r != '>'
}

func (htmlSafeJSONStringCharacterEscapingBehaviorStruct) UseShorthandEscapeSequence(_ rune) bool {
	return true
}

func createUnexpectedErrorErrorPageHTML(requestId string) string {
	pageTitle := "An unexpected error occurred | Passwordless auth example"

	bodyHTML := `<h1>An unexpected error occurred</h1>
<p>Something went wrong. Please refresh the page or try again later.</p>`

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, "", "", "")

	return pageHTML
}

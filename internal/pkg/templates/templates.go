package templates

import (
	"html/template"
	"io"
)

// Template represents html templates
type Template interface {
	ExecuteTemplate(io.Writer, string, interface{})
}

// HTMLTemplate is a wrapper around html/template package
type HTMLTemplate struct {
	templates *template.Template
}

// ExecuteTemplate wraps the html/template ExecuteTemplate function
func (ht *HTMLTemplate) ExecuteTemplate(rw io.Writer, path string, data interface{}) {
	ht.templates.ExecuteTemplate(rw, path, data)
}

// NewHTMLTemplate returns a new HTMLTemplate
func NewHTMLTemplate() *HTMLTemplate {
	t := template.New("foo")
	template.Must(t.Parse(`{{define "header.html"}}
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<link rel="stylesheet" type="text/css" href="/static/sso.css">
{{end}}`))

	t = template.Must(t.Parse(`{{define "footer.html"}}
Secured by <b>SSO</b>{{end}}`))

	t = template.Must(t.Parse(`{{define "sign_in_message.html"}}
  {{if eq (len .EmailDomains) 1}}
      {{if eq (index .EmailDomains 0) "@*"}}
          <p>You may sign in with any {{.ProviderSlug}} account.</p>
      {{else}}
          <p>You may sign in with your <b>{{index .EmailDomains 0}}</b> {{.ProviderSlug}} account.</p>
      {{end}}
  {{else if gt (len .EmailDomains) 1}}
      <p>
          You may sign in with any of these {{.ProviderSlug}} accounts:<br>
          {{range $i, $e := .EmailDomains}}{{if $i}}, {{end}}<b>{{$e}}</b>{{end}}
      </p>
  {{end}}
{{end}}`))

	t = template.Must(t.Parse(`{{define "sign_in.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
	<title>Sign In</title>
	{{template "header.html"}}
</head>


<body>
    <div class="container">
        <div class="content">
            <header>
                <h1>Sign in to <b>{{.Destination}}</b></h1>
            </header>

            {{template "sign_in_message.html" .}}

            <form method="GET" action="{{.Action}}">
                <input type="hidden" name="redirect_uri" value="{{.SignInParams.RedirectURL}}">
                <input type="hidden" name="scope" value="{{.SignInParams.Scope}}">
                <input type="hidden" name="client_id" value="{{.SignInParams.ClientID}}">
                <input type="hidden" name="response_type" value="{{.SignInParams.ResponseType}}">
                <input type="hidden" name="state" value="{{.SignInParams.State}}">
                <input type="hidden" name="ts" value="{{.SignInParams.TimeStamp}}">
                <input type="hidden" name="sig" value="{{.SignInParams.Signature}}">
                <button type="submit" class="btn">Sign in with {{.ProviderSlug}}</button>
            </form>
        </div>

        <footer>{{template "footer.html"}}</footer>
    </div>
</body>
</html>
{{end}}`))

	template.Must(t.Parse(`{{define "error.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
	<title>Error</title>
	{{template "header.html"}}
</head>
<body>
    <div class="container">
      <div class="content error">
        <header>
            <h1>{{.Title}}</h1>
        </header>
        <p>
          {{.Message}}<br>
          <span class="details">HTTP {{.Code}}</span>
        </p>
    </div>
        <footer>{{template "footer.html"}}</footer>
    </div>
</body>
</html>{{end}}`))

	t = template.Must(t.Parse(`{{define "sign_out.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
	<title>Sign Out</title>
	{{template "header.html"}}
</head>
<body>
    <div class="container">
    	<div class="content">
            <header>
                <h1>Sign out of <b>{{.Destination}}</b></h1>
            </header>

            <p>You're currently signed in as <b>{{.Email}}</b>. This will also sign you out of other internal apps.</p>
            <form method="POST" action="{{.Action}}">
              <input type="hidden" name="redirect_uri" value="{{.SignOutParams.RedirectURL}}">
              <input type="hidden" name="sig" value="{{.SignOutParams.Signature}}">
              <input type="hidden" name="ts" value="{{.SignOutParams.TimeStamp}}">
              <button type="submit">Sign out</button>
            </form>
    	</div>
    	<footer>{{template "footer.html"}}</footer>
    </div>
</body>
</html>
{{end}}`))
	return &HTMLTemplate{t}
}

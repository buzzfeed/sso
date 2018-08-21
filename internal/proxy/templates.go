package proxy

import (
	"html/template"
)

func getTemplates() *template.Template {
	t := template.New("foo")
	t = template.Must(t.Parse(`{{define "error.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
  <title>Error</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<style>
* {
  margin: 0;
  padding: 0;
}
body {
  font-family: "Helvetica Neue",Helvetica,Arial,sans-serif;
  font-size: 1em;
  line-height: 1.42857143;
  color: #333;
  background: #f0f0f0;
}

p {
  margin: 1.5em 0;
}
p:first-child {
  margin-top: 0;
}
p:last-child {
  margin-bottom: 0;
}

.container {
  max-width: 40em;
  display: block;
  margin: 10% auto;
  text-align: center;
}

.content, .message, button {
  border: 1px solid rgba(0,0,0,.125);
  border-bottom-width: 4px;
  border-radius: 4px;
}

.content, .message {
  background-color: #fff;
  padding: 2rem;
  margin: 1rem 0;
}
.error, .message {
    border-bottom-color: #c00;
}
.message {
    padding: 1.5rem 2rem 1.3rem;
}

header {
  border-bottom: 1px solid rgba(0,0,0,.075);
  margin: -2rem 0 2rem;
  padding: 2rem 0 1.8rem;
}
header h1 {
  font-size: 1.5em;
  font-weight: normal;
}
.error header {
    color: #c00;
}
.details {
    font-size: .85rem;
    color: #999;
}

button {
  color: #fff;
  background-color: #3B8686;
  cursor: pointer;
  font-size: 1.5rem;
  font-weight: bold;
  padding: 1rem 2.5rem;
  text-shadow: 0 3px 1px rgba(0,0,0,.2);
  outline: none;
}
button:active {
  border-top-width: 4px;
  border-bottom-width: 1px;
  text-shadow: none;
}

footer {
  font-size: 0.75em;
  color: #999;
  text-align: right;
  margin: 1rem;
}
</style>
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
      {{if ne .Code 403 }}
        <form method="GET" action="/">
          <button>Sign in</button>
        </form>
      {{end}}
    </div>
    <footer>Secured by <b>SSO</b></footer>
  </div>
</body>
</html>{{end}}`))
	return t
}

package main

const pageTemplates = `
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Formwork</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--fg:#e6e9ef;--mut:#8b93a7;--acc:#3ddc84}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif}
a{color:var(--acc);text-decoration:none}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;gap:14px;align-items:baseline}
header .brand{font-weight:700;letter-spacing:.5px}
header .tag{color:var(--mut);font-size:13px}
main{max-width:920px;margin:0 auto;padding:22px 20px 60px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:16px 0}
h1{font-size:22px;margin:6px 0 2px}
h2{font-size:16px;margin:0 0 10px;color:#cfd5e2}
label{display:block;font-size:13px;color:var(--mut);margin:8px 0 3px}
input[type=text]{width:100%;padding:8px 10px;background:#0c0e12;border:1px solid var(--line);border-radius:7px;color:var(--fg)}
button{background:var(--acc);color:#04140b;border:0;border-radius:7px;padding:8px 14px;font-weight:600;cursor:pointer}
button.ghost{background:#222836;color:var(--fg)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}
code{background:#0c0e12;padding:1px 6px;border-radius:5px;font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
.row form{flex:1;min-width:200px}
.mut{color:var(--mut)}
.err{background:#2a1417;border:1px solid #5a2530;color:#ffb4bd;padding:10px 12px;border-radius:8px}
.ok{background:#12251a;border:1px solid #244f35;color:#9be8bd;padding:10px 12px;border-radius:8px}
.note{white-space:pre-wrap;word-break:break-all}
.fp{font-family:ui-monospace,Menlo,monospace;color:#9aa4bd}
</style></head><body>
<header><span class="brand">FORMWORK</span><span class="tag">low-code base builder</span></header>
<main>{{end}}

{{define "foot"}}</main></body></html>{{end}}

{{define "index"}}{{template "head" .}}
<h1>Bases</h1>
<p class="mut">Create a base, shape its fields, then seal it to sign the schema.</p>
<div class="panel">
<h2>New base</h2>
<form method="post" action="/bases" class="row">
<div style="flex:1"><label>Name</label><input type="text" name="name" placeholder="Inventory"></div>
<div><label>&nbsp;</label><button type="submit">Create</button></div>
</form>
</div>
<div class="panel">
<h2>Your bases</h2>
{{if .Bases}}<table><thead><tr><th>Name</th><th>Id</th></tr></thead><tbody>
{{range .Bases}}<tr><td><a href="/bases/{{.ID}}">{{.Name}}</a></td><td><code>{{.ID}}</code></td></tr>{{end}}
</tbody></table>{{else}}<p class="mut">No bases yet.</p>{{end}}
</div>
{{template "foot" .}}{{end}}

{{define "base"}}{{template "head" .}}
<p><a href="/">&larr; bases</a></p>
<h1>{{.Base.Name}}</h1>
<p class="mut">base id <code>{{.Base.ID}}</code></p>
{{if .SealError}}<div class="panel"><div class="err">{{.SealError}}</div></div>{{end}}
{{if .Notice}}<div class="panel"><div class="ok">{{.Notice}}</div></div>{{end}}

<div class="panel">
<h2>Fields</h2>
{{if .Fields}}<table><thead><tr><th>Label</th><th>Identifier</th><th></th></tr></thead><tbody>
{{range .Fields}}<tr>
<td>{{.Label}}</td>
<td><code>{{.ColIdent}}</code></td>
<td>
<form method="post" action="/bases/{{$.Base.ID}}/fields/{{.FieldID}}/rename" style="display:inline-flex;gap:6px">
<input type="text" name="label" placeholder="rename" style="width:130px">
<button class="ghost" type="submit">rename</button>
</form>
<form method="post" action="/bases/{{$.Base.ID}}/fields/{{.FieldID}}/drop" style="display:inline">
<button class="ghost" type="submit">drop</button>
</form>
</td></tr>{{end}}
</tbody></table>{{else}}<p class="mut">No fields yet.</p>{{end}}
<form method="post" action="/bases/{{.Base.ID}}/fields" class="row" style="margin-top:12px">
<div style="flex:1"><label>Add field</label><input type="text" name="label" placeholder="Quantity"></div>
<div><label>&nbsp;</label><button type="submit">Add</button></div>
</form>
</div>

<div class="panel">
<h2>Records</h2>
{{if .Columns}}
<table><thead><tr>{{range .Columns}}<th>{{.}}</th>{{end}}</tr></thead><tbody>
{{range .Records}}<tr>{{$rec:=.}}{{range $.Columns}}<td>{{index $rec .}}</td>{{end}}</tr>{{end}}
</tbody></table>
<form method="post" action="/bases/{{.Base.ID}}/records" class="row" style="margin-top:12px">
{{range .Columns}}<div><label>{{.}}</label><input type="text" name="{{.}}"></div>{{end}}
<div><label>&nbsp;</label><button type="submit">Add row</button></div>
</form>
{{else}}<p class="mut">Add a field to start entering records.</p>{{end}}
</div>

<div class="panel">
<h2>Seal</h2>
<p class="mut">Sealing folds every field into a signed rollup so later drift is detectable.</p>
<form method="post" action="/bases/{{.Base.ID}}/seal"><button type="submit">Seal base</button></form>
{{if .Rollup.Present}}
<div style="margin-top:14px">
<div class="mut">fingerprint</div>
<div class="fp">{{.Rollup.Fingerprint}}</div>
<div class="mut" style="margin-top:10px">components</div>
<div class="note">{{.Rollup.Note}}</div>
<div class="mut" style="margin-top:8px">sealed {{.Rollup.ComputedAt}}</div>
</div>
{{else}}<p class="mut" style="margin-top:12px">Not sealed yet.</p>{{end}}
</div>
{{template "foot" .}}{{end}}
`

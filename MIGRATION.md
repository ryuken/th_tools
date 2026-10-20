# Migrating from v0.1.x to v0.2.0

v0.2.0 is a security release. It fixes an authentication bypass, replaces
unsalted SHA-512 password hashes with bcrypt and drops two unmaintained
dependencies (`gopkg.in/mgo.v2` and `github.com/gorilla/context`). Some of
these changes require updates in your application.

## Checklist

1. [Upgrade Go to 1.25 or newer](#1-upgrade-go-and-th_tools)
2. [Add `session_key` to `config.json`](#2-add-session_key-to-configjson)
3. [Replace `gorilla/context` with `th_tools.WithValue` / `th_tools.Value`](#3-replace-gorillacontext)
4. [Pass a `*mongo.Client` instead of an `*mgo.Session`](#4-switch-from-mgo-to-the-official-mongodb-driver) (AccountMGO users only)
5. [Send tokens via cookie or `Authorization` header, not `?access_token=`](#5-stop-sending-tokens-in-the-url) (AccountMGO users only)
6. [Update calls to `ConvertPassword` and `Sanitize`](#6-password-hashing)
7. [Check that remote servers support TLS 1.2](#7-tls-12-is-now-required-in-requestdo) (Request users only)
8. [Optional: use placeholders in the SQL builder](#8-optional-sql-builder-placeholders)

## 1. Upgrade Go and th_tools

v0.2.0 requires Go 1.25 or newer.

```sh
go get github.com/ryuken/th_tools@v0.2.0
go mod tidy
```

## 2. Add `session_key` to `config.json`

The cookie store used by `AccountMGO` was signed with a hardcoded key that
was public in this repository, so anyone could forge session cookies. The
key now comes from your config and must be at least 32 characters:

```json
{
    "secret": "your-jwt-secret",
    "session_key": "at-least-32-random-characters-here"
}
```

Generate one with:

```sh
openssl rand -base64 48
```

Without a valid `session_key`, `AccountMGO.Validate`, `Check` and
`RequireLogin` refuse every request and log
`config: session_key must be at least 32 characters`.

Keep `session_key` and `secret` out of version control. Changing
`session_key` logs everyone out.

## 3. Replace `gorilla/context`

`gorilla/context` stores values per `*http.Request` pointer. Routers such as
`gorilla/mux` copy the request, so values set before routing could silently
disappear. th_tools now uses the standard request context.

Values are still stored under the same keys (`"config"`, `"db"`,
`"session-store"`, `"mongodb"`, `"system"`, `"session"`). Only the way you set
and read them changes.

| v0.1.x | v0.2.0 |
| --- | --- |
| `context.Set(r, "db", db)` | `r = th_tools.WithValue(r, "db", db)` |
| `context.Get(r, "session")` | `th_tools.Value(r, "session")` |

`WithValue` returns a new request, so you must pass the returned request on
to the next handler. A typical middleware:

Before:

```go
func withDeps(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		context.Set(r, "config", config)
		context.Set(r, "db", db)
		context.Set(r, "session-store", store)
		context.Set(r, "system", 1)
		next.ServeHTTP(w, r)
	})
}
```

After:

```go
func withDeps(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = th_tools.WithValue(r, "config", config)
		r = th_tools.WithValue(r, "db", db)
		r = th_tools.WithValue(r, "session-store", store)
		r = th_tools.WithValue(r, "system", 1)
		next.ServeHTTP(w, r)
	})
}
```

Register the middleware on the router so it runs for every route:

```go
ht := th_tools.HttpTool{}
ht.Init()
ht.Router.Use(withDeps)
```

Handlers behind `AccountSQL.RequireLogin` that read the current session
change the same way:

```go
sess := th_tools.Value(r, "session").(th_tools.Session)
```

You can then remove `github.com/gorilla/context` from your own `go.mod`, as
well as any `context.ClearHandler` wrapper.

## 4. Switch from mgo to the official MongoDB driver

*Only if you use `AccountMGO`.*

`gopkg.in/mgo.v2` has been unmaintained since 2019. `AccountMGO` now uses
[`go.mongodb.org/mongo-driver/v2`](https://pkg.go.dev/go.mongodb.org/mongo-driver/v2/mongo),
and expects a `*mongo.Client` under the `"mongodb"` key.

Before:

```go
session, err := mgo.Dial("mongodb://localhost")
// ...
context.Set(r, "mongodb", session)
```

After:

```go
import (
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

client, err := mongo.Connect(options.Client().ApplyURI("mongodb://localhost"))
if err != nil {
	log.Fatal(err)
}
defer client.Disconnect(context.Background())
// ...
r = th_tools.WithValue(r, "mongodb", client)
```

Create one client at startup and share it. Unlike `mgo.Session`, you don't
need to `Copy()` it per request.

The `Id` fields on `AccountMGO`, `System` and `AccountSystem` are now
`bson.ObjectID` from `go.mongodb.org/mongo-driver/v2/bson` instead of
`bson.ObjectId` from mgo. Update any code that builds or compares them, for
example `bson.ObjectIdHex(s)` becomes `bson.ObjectIDFromHex(s)`.

Existing documents don't need any changes. Field names in the database stay
the same.

### JWT `_id` claim

The `_id` claim in tokens issued by `AccountMGO.Validate` is now the plain
hex id (`"5f1d7c..."`) instead of `ObjectIdHex("5f1d7c...")`. If you parse
this claim, update your parsing.

Tokens issued by v0.1.x were never valid (the `iat` claim was written in a
format the JWT library rejects), so users have to log in again after the
upgrade.

## 5. Stop sending tokens in the URL

*Only if you use `AccountMGO`.*

`AccountMGO.Check` and `RequireLogin` no longer read the `access_token`
query parameter, because URLs end up in server logs, browser history and
`Referer` headers. They read the token from:

1. the session cookie set by `Validate` (browsers send this automatically), or
2. an `Authorization` header:

```
Authorization: Bearer <token>
```

Update API clients that send `?access_token=...`.

Other behavior changes:

- Expired tokens are always rejected; clients must log in again after the
  1-hour expiry.
- Tokens signed with anything other than HMAC are rejected.
- The session cookie now expires after 1 hour instead of ~56 years.
- `RequireLogin` now actually blocks requests with a missing or invalid
  token. Previously it passed them on to your handler. If an endpoint
  behind it was meant to be public, take it out from behind `RequireLogin`.

## 6. Password hashing

Passwords are now hashed with bcrypt.

**Existing users keep working.** On their next successful login, their old
SHA-512 hash is verified and replaced with a bcrypt hash automatically. You
don't need to run a migration or reset passwords. Your password column must
hold at least 60 characters; a column sized for SHA-512 (128) is fine.

If your code calls these methods directly:

- `ConvertPassword()` on `AccountMGO` and `AccountSQL` now produces a bcrypt
  hash and returns an `error`:

  ```go
  if err := account.ConvertPassword(); err != nil {
  	// bcrypt rejects passwords longer than 72 bytes
  }
  ```

- `AccountMGO.Sanitize` no longer hashes the password. Call
  `ConvertPassword()` after it before storing a new account.

- Never compare stored hashes yourself (for example
  `WHERE password = ?`); bcrypt hashes differ every time. Use the new
  helpers instead:

  ```go
  hash, err := th_tools.HashPassword(password)

  ok, rehash := th_tools.CheckPassword(storedHash, password)
  // rehash is true for a legacy SHA-512 hash: store HashPassword(password)
  ```

`AccountSQL.Validate` also no longer writes the request body (including the
plaintext password) to the log.

## 7. TLS 1.2 is now required in `Request.Do`

`Request.Do` used to force TLS 1.0 with a single legacy cipher. It now
requires TLS 1.2 or newer and uses Go's default cipher suites. If a server
you call only supports TLS 1.0 or 1.1, requests to it fail with a handshake
error. Upgrade that server; there is no option to re-enable TLS 1.0.

## 8. Optional: SQL builder placeholders

*This change is backward compatible; existing code keeps working.*

`sql.Select`, `sql.Update` and `sql.Insert` insert every fragment directly
into the SQL string. If any of those fragments contain user input, your
queries are open to SQL injection. You can now pass values separately as
`?` placeholders and run the query with `Params()`:

Before:

```go
s := sql.Select{Table: "accounts"}
s.Set("id")
s.Where("email = '" + email + "'") // injectable
rows, err := sql.FlexFetch{}.Select(db, s.ToSQL(), nil)
```

After:

```go
s := sql.Select{Table: "accounts"}
s.Set("id")
s.Where("email = ?", email)
rows, err := sql.FlexFetch{}.Select(db, s.ToSQL(), s.Params())
```

`Set`, `Where`, `And`, `Or` and `Join` accept optional values. For inserts,
use `i.Set("?", value)`.

Table names, column names, `GroupBy` and `OrderBy` can't be placeholders.
If they come from user input (for example a sort column), check them
against a fixed list of allowed values.

Also fixed: `LimitRange(offset, limit)` now applies the offset (it was
ignored before), and `FlexFetch` closes its result rows, which previously
leaked database connections.

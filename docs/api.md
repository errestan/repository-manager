# Publishing from CI

Repository Manager's web interface is for people. The REST API is for build pipelines, and
it does exactly the same things through exactly the same code: an upload from a shell script
is validated, stored, audited and indexed by the same service call the browser form uses
(specification.md §8.2).

Everything below assumes two environment variables:

```sh
REPOMAN_URL=https://packages.example.com
REPOMAN_TOKEN=rmt_...            # from the tokens page; treat it as a password
```

The interactive reference — every endpoint, every parameter, every status code — is served
by the instance itself at `$REPOMAN_URL/api/docs`, and the machine-readable schema at
`$REPOMAN_URL/api/v1/openapi.json`. This document is the narrative half: how to get a token,
what a pipeline should do with it, and what to do when it stops working.

## Getting a token

Sign in, open **Tokens**, and create one. You choose four things:

| Field | What it does |
|---|---|
| Label | How you recognise it later. Nothing else uses it. |
| Permissions | `package:read` and `package:write`. A pipeline that publishes needs `package:write`. |
| Repositories | Tick the ones this token may act on. Leave every box clear to allow all of them, including ones added later. |
| Valid for | Days. The default is 90 and the instance sets a ceiling. |

The token is shown **once**, on the page that appears immediately after you create it. It is
stored only as a SHA-256, so there is no way to read it back — if it is lost, revoke it and
create another.

Two properties are worth understanding before you rely on one.

**A token can never do more than you can.** What it may do is its permissions intersected
with your role in the directory *at the time of the request*, re-checked every few minutes.
If your account leaves the maintainer group, every token you hold stops being able to write,
without anyone having to revoke it. This is deliberate: the alternative is a credential that
outlives the access it was granted from.

**Scope it to the repositories it needs.** A token restricted to `internal` cannot publish
to, remove from, or regenerate anything else — and cannot even see the jobs belonging to
other repositories.

## Publishing a package

An upload is one `POST` with the file and its target.

For an APT repository:

```sh
curl --fail-with-body --silent \
  --header "Authorization: Bearer $REPOMAN_TOKEN" \
  --form file=@build/hello_1.0-1_amd64.deb \
  --form distribution=bookworm \
  --form component=main \
  "$REPOMAN_URL/api/v1/repositories/internal/packages"
```

For an RPM repository, the target is a variant, written as `name/arch`:

```sh
curl --fail-with-body --silent \
  --header "Authorization: Bearer $REPOMAN_TOKEN" \
  --form file=@build/hello-1.0-1.el9.x86_64.rpm \
  --form variant=el9/x86_64 \
  "$REPOMAN_URL/api/v1/repositories/el9/packages"
```

The targets a repository offers are in its own record, so a script does not have to guess:

```sh
curl --silent "$REPOMAN_URL/api/v1/repositories/internal" | jq '.distributions'
```

The architecture is read from the package, never from the request. Nor is the filename you
send used for anything: the stored path is derived from the parsed metadata (§10.2), so a
package uploaded as `artifact.deb` still lands at `pool/main/h/hello/hello_1.0-1_amd64.deb`.

### What the answers mean

| Status | Meaning |
|---|---|
| `201` | Published. `job_id` names the metadata rebuild. |
| `200` | The byte-identical file was already published here. Nothing changed, `job_id` is null. |
| `409` | That version exists with **different** contents. Publish a new version. |
| `400` | The target is missing or the file is not a package of the expected format. |
| `403` | The token lacks `package:write`, or is scoped to other repositories, or its owner has lost their role. |
| `413` | Larger than `REPOMAN_MAX_UPLOAD_BYTES`. |

The `200` is the one that makes retries safe: a pipeline step that runs twice — because a
runner was replaced, because someone re-ran the job — succeeds both times. The `409` is the
one that never softens. Overwriting a published version with different bytes would leave
clients that already installed the old file with no way to find out.

## Waiting for publication

Publishing is two steps, and the API tells you about both. The upload writes the file and
the database row; a background job rebuilds the repository metadata (§5.4). Until that job
succeeds, `apt` and `dnf` will not see the package.

If the next step in your pipeline installs what you just published, wait:

```sh
upload=$(curl --fail-with-body --silent \
  --header "Authorization: Bearer $REPOMAN_TOKEN" \
  --form file=@build/hello_1.0-1_amd64.deb \
  --form distribution=bookworm \
  --form component=main \
  "$REPOMAN_URL/api/v1/repositories/internal/packages")

job=$(printf '%s' "$upload" | jq -r '.job_id // empty')

while [ -n "$job" ]; do
  state=$(curl --fail-with-body --silent \
    --header "Authorization: Bearer $REPOMAN_TOKEN" \
    "$REPOMAN_URL/api/v1/jobs/$job" | jq -r .state)
  case "$state" in
    succeeded) break ;;
    failed|cancelled)
      echo "publication $state" >&2
      curl --silent --header "Authorization: Bearer $REPOMAN_TOKEN" \
        "$REPOMAN_URL/api/v1/jobs/$job" | jq -r '.error, .log' >&2
      exit 1 ;;
  esac
  sleep 2
done
```

Uploading several packages before waiting is both allowed and faster: regeneration requests
for one repository coalesce into a single job (§5.4), so publishing twenty packages rebuilds
the metadata once rather than twenty times. Poll the job id from the *last* upload.

Reading a job needs a token — unlike the other reads — because a job record carries the log
of whatever ran, including the tail of a failed subprocess.

## Errors

Every failure is a [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) problem document:

```json
{
  "type": "urn:repository-manager:problem:conflict",
  "title": "Conflict",
  "status": 409,
  "detail": "hello 1.0-1 (amd64) is already published with different contents. Publish a new version rather than replacing one clients may already have installed.",
  "instance": "/api/v1/repositories/internal/packages"
}
```

`detail` is written to be read in a failed build log, so printing it is usually enough.
`type` is stable across versions and deployments, so branch on that rather than on the
prose:

| `type` | When |
|---|---|
| `…:conflict` | A different file already holds that version |
| `…:not-found` | No such repository, target, package or job |
| `…:forbidden` | The token may not do this |
| `…:unauthenticated` | No token, or one that is expired or revoked |
| `…:upload-too-large` | Over the configured limit |
| `…:unavailable` | The directory could not be reached to confirm permissions; retry |

`curl` does not fail on a 4xx by default. Use `--fail-with-body`, which sets a non-zero exit
status *and* still prints the document — plain `--fail` discards the explanation.

## GitHub Actions

```yaml
- name: Publish to the internal repository
  env:
    REPOMAN_URL: https://packages.example.com
    REPOMAN_TOKEN: ${{ secrets.REPOMAN_TOKEN }}
  run: |
    curl --fail-with-body --silent \
      --header "Authorization: Bearer $REPOMAN_TOKEN" \
      --form file=@dist/hello_${{ github.ref_name }}_amd64.deb \
      --form distribution=bookworm \
      --form component=main \
      "$REPOMAN_URL/api/v1/repositories/internal/packages"
```

## GitLab CI

```yaml
publish:
  stage: deploy
  variables:
    REPOMAN_URL: https://packages.example.com
  script:
    - |
      curl --fail-with-body --silent \
        --header "Authorization: Bearer $REPOMAN_TOKEN" \
        --form file=@dist/hello-${CI_COMMIT_TAG}.el9.x86_64.rpm \
        --form variant=el9/x86_64 \
        "$REPOMAN_URL/api/v1/repositories/el9/packages"
```

`REPOMAN_TOKEN` should be a masked, protected CI/CD variable.

## Removing a package

Removal is per publication target, not per file: a package published to two components is
removed from one and stays in the other. The id to use is the `id` from a package listing.

```sh
id=$(curl --silent \
  "$REPOMAN_URL/api/v1/repositories/internal/packages?name=hello&arch=amd64" \
  | jq -r '.packages[0].id')

curl --fail-with-body --silent --request DELETE \
  --header "Authorization: Bearer $REPOMAN_TOKEN" \
  "$REPOMAN_URL/api/v1/repositories/internal/packages/$id"
```

The response's `file_deleted` says whether the pool file went too, or whether another target
still references it.

## Checking what is published

Listings are anonymous — no token needed, the same as browsing the site. `name` is an
**exact** match, unlike the search box in the web interface, so asking about `libfoo` does
not also return `libfoo-dev`.

```sh
# Is this exact version live?
curl --silent \
  "$REPOMAN_URL/api/v1/repositories/internal/packages?name=hello&arch=amd64" \
  | jq -r '.packages[] | .full_version'

# Everything in one component.
curl --silent \
  "$REPOMAN_URL/api/v1/repositories/internal/packages?distribution=bookworm&component=main"
```

Results are paginated: `page` and `per_page` (default 100, maximum 500), with `total` and
`pages` in the response.

## When something stops working

**`401` on every request.** The token is expired or revoked; both answer identically, on
purpose. Check the tokens page and mint a replacement.

**`403` that says the owner is no longer a member of a permitted group.** The account that
minted the token has lost its directory role. The token is not the problem — restoring the
group membership brings it back, or someone else can mint one.

**`403` naming a scope.** The token was created without `package:write`. Permissions cannot
be changed after minting; create a new token and revoke the old one.

**`503` mentioning the directory.** The LDAP server could not be reached to confirm the
token owner's role. Retry — the response carries `Retry-After`. Reads keep working
throughout, because they do not need a role.

**Uploads succeed but `apt`/`dnf` do not see the package.** The regeneration job has not
finished, or it failed. Poll `GET /api/v1/jobs/{id}` and read its `error` and `log`.

## UserEncryption with shared documents using asymmetric encryption (public-private key pair)

Repository for blog post on user encryption in Elixir using asymmetric encryption
https://medium.com/@badu_bizzle/per-user-encryption-in-elixir-iii-6a5760a8a779
https://medium.com/swlh/per-user-encryption-with-elixir-iv-a56a1fbe8d4a?source=friends_link&sk=652f900c4b8a6084c3d92b8081ee58f5


Check out previous posts using symmetric encryption
https://medium.com/@badu_bizzle/per-user-encryption-in-elixir-part-i-645f2dfaf8e6
https://medium.com/@badu_bizzle/per-user-encryption-in-elixir-part-ii-fd984017fb7d

Repo: https://github.com/badubizzle/user_encryption

## Cloning and Running tests

1. Clone repo
2. Install dependencies `mix deps.get`
3. Run test `mix test`
4. Run `iex -S mix`

## Examples

### Creating new database

```elixir
alias UserEncryption.Database

db = Database.new()
```

### Add a user

```elixir

username = "jose"
password = "12345"
{:ok, db} = Database.add_user(db, %{username: username, password: password})
```

## Encrypt a document for a user

```elixir
jose = Database.get_user(db, username)
content = "Hello world!"
{:ok, doc, db} = Database.add_document(db, jose, password, content)

{:ok, ^content} = Database.decrypt_document(db, doc, jose, password)

```

## Updating Encrypted document

```elixir
new_content = "Updated Hello world!"
{:ok, doc, db} = Database.update_document(db, doc, jose, password, new_content)

{:ok, ^new_content} = Database.decrypt_document(db, doc, jose, password)

```

## Share Encrypted document with other users

```elixir
# add a new user
joe_password = "123456"
{:ok, db} = Database.add_user(db, %{username: "joe", password: joe_password})

joe = Database.get_user(db, "joe")

# jose shares document with joe
{:ok, db} = Database.share_document(db, jose, joe, doc, password)

# joe can now decrypt document
{:ok, ^new_content} = Database.decrypt_document(db, doc, joe, joe_password)

# joe can also update the document
joe_content = "Updated doc from joe!"
{:ok, doc, db} = Database.update_document(db, doc, joe, joe_password, joe_content)

# jose should be able to read the updated document

{:ok, ^joe_content} = Database.decrypt_document(db, doc, jose, password)
```

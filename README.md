# UserEncryption with shared documents using public private keys

## Cloning and Running tests

1. Clone repo
2. Install dependencies `mix deps.get`
3. Run test `mix test`

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

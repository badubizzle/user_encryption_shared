defmodule UserEncryptionTest do
  use ExUnit.Case
  doctest UserEncryption

  alias UserEncryption.Database
  alias UserEncryption.Utils

  @content "Hello world"
  @password Utils.generate_key()
  @username "badu"
  @new_content "Welcome!"

  setup %{} do
    db = Database.new()
    {:ok, db} = Database.add_user(db, %{username: @username, password: @password})
    user = Database.get_user(db, @username)
    {:ok, doc, db} = Database.add_document(db, user, @password, @content)
    {:ok, %{db: db, doc: doc, user: user}}
  end

  def get_new_user() do
    username =
      Utils.generate_key()
      |> String.to_charlist()
      |> Enum.take(6)
      |> List.to_string()

    %{username: username, password: Utils.generate_key()}
  end

  test "greets the world" do
    assert UserEncryption.hello() == :world
  end

  test "create user", %{db: db} do
    user = get_new_user()
    {:ok, db} = Database.add_user(db, user)
    assert Database.get_user(db, user.username) != nil
  end

  test "validate user password", %{db: db, user: user} do
    assert :ok = Database.login_user(db, %{username: user.username, password: @password})
  end

  test "invalid user password", %{db: db, user: user} do
    assert :error = Database.login_user(db, %{username: user.username, password: "1234"})
  end

  test "add encrypted document", %{db: db, user: user} do
    {:ok, doc, _db} = Database.add_document(db, user, @password, @content)
    assert doc != nil
  end

  test "decrypt document with password", %{db: db, user: user, doc: doc} do
    assert {:ok, @content} == Database.decrypt_document(db, doc, user, @password)
  end

  test "decrypt document with wrong password", %{db: db, user: user, doc: doc} do
    assert {:error, :failed_verification} == Database.decrypt_document(db, doc, user, "123")
  end

  test "update encrypted document", %{db: db, user: user, doc: doc} do
    {:ok, new_doc, db} = Database.update_document(db, doc, user, @password, @new_content)
    assert doc.id == new_doc.id
    assert {:ok, @new_content} == Database.decrypt_document(db, new_doc, user, @password)
  end

  test "share encrypted document", %{db: db, user: from_user, doc: doc} do
    new_user = get_new_user()
    {:ok, db} = Database.add_user(db, new_user)

    to_user = Database.get_user(db, new_user.username)

    {:ok, db} = Database.share_user_document(db, from_user, to_user, doc, @password)

    # new user should be able to decrypt document with their keys
    assert {:ok, @content} == Database.decrypt_document(db, doc, to_user, new_user.password)
  end
end

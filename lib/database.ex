defmodule UserEncryption.Database do
  defstruct users: %{},
            documents: %{},
            user_documents: %{}

  alias UserEncryption.Utils
  alias UserEncryption.KeyPair
  alias UserEncryption.User
  alias UserEncryption.EncryptedDocument
  alias UserEncryption.UserDocument
  alias __MODULE__

  @type t :: %__MODULE__{
          users: Map.t(),
          documents: Map.t(),
          user_documents: Map.t()
        }

  @spec new :: t()
  def new() do
    struct!(__MODULE__)
  end

  @spec get_user(Database.t(), username :: binary) :: User.t() | nil
  def get_user(%__MODULE__{} = db, username) do
    case Map.get(db.users, username, nil) do
      %User{} = u -> u
      _ -> nil
    end
  end

  @spec login_user(Database.t(), %{password: binary, username: any}) ::
          :error | :ok
  def login_user(%__MODULE__{} = db, %{username: username, password: password}) do
    with user <- Map.get(db.users, username),
         {:ok, _key} <- Utils.decrypt_key_hash(password, user.key_hash) do
      :ok
    else
      _ -> :error
    end
  end

  @spec add_user(Database.t(), %{password: binary, username: binary}) ::
          {:error, binary} | {:ok, Database.t()}
  def add_user(
        %__MODULE__{} = db,
        %{username: username, password: password}
      ) do
    user = User.new(username, password)

    case Map.get(db.users, user.username) do
      nil ->
        users = Map.put(db.users, user.username, user)
        {:ok, %__MODULE__{db | users: users}}

      _ ->
        {:error, "User exists"}
    end
  end

  @spec decrypt_document(
          Database.t(),
          User.t(),
          EncryptedDocument.t(),
          binary
        ) :: {:ok, binary} | {:error, any}
  def decrypt_document(
        %__MODULE__{} = db,
        %User{key_pair: %KeyPair{private_hash: private_key_hash}} = user,
        %EncryptedDocument{} = document,
        password
      ) do
    user_doc_id = "#{user.username}-#{document.id}"

    case Map.get(db.user_documents, user_doc_id) do
      %{user_key: user_document_key} ->
        with {:ok, user_key} <-
               Utils.decrypt_key_hash(password, user.key_hash),
             {:ok, priv_key} <-
               Utils.decrypt(%{key: user_key, payload: private_key_hash}),
             {:ok, document_key} <-
               Utils.decrypt_message_for_user(
                 user_document_key,
                 %{public: user.key_pair.public, private: priv_key}
               ) do
          Utils.decrypt(%{
            key: document_key,
            payload: document.data_hash
          })
        else
          e -> e
        end

      _ ->
        {:error, "No document found"}
    end
  end

  @spec update_document(
          Database.t(),
          EncryptedDocument.t(),
          User.t(),
          any,
          any
        ) ::
          {:error, :failed_verification | binary}
          | {:ok, EncryptedDocument.t(), Database.t()}
  def update_document(
        db,
        document,
        %User{key_pair: %KeyPair{public: public_key, private_hash: private_key_hash}} = user,
        password,
        new_content
      ) do
    user_doc_id = "#{user.username}-#{document.id}"

    case Map.get(db.user_documents, user_doc_id) do
      %{user_key: user_document_key} ->
        with {:ok, user_key} <-
               Utils.decrypt_key_hash(password, user.key_hash),
             {:ok, priv_key} <-
               Utils.decrypt(%{key: user_key, payload: private_key_hash}),
             {:ok, document_key} <-
               Utils.decrypt_message_for_user(
                 user_document_key,
                 %{public: public_key, private: priv_key}
               ) do
          {:ok, _} =
            Utils.decrypt(%{
              key: document_key,
              payload: document.data_hash
            })

          doc = EncryptedDocument.new(new_content, document_key, document.id)

          documents = Map.put(db.documents, doc.id, doc)
          {:ok, doc, %__MODULE__{db | documents: documents}}
        else
          {:error, e} -> {:error, e}
          e -> {:error, e}
        end

      _ ->
        {:error, "Invalid doc"}
    end
  end

  @spec add_document(Databae.t(), User.t(), content :: binary) ::
          {:ok, EncryptedDocument.t(), Database.t()}
  def add_document(%__MODULE__{} = db, %User{} = user, content) do
    document_key = Utils.generate_key()
    doc = EncryptedDocument.new(content, document_key)
    user_document = UserDocument.new(user, doc, document_key)
    documents = Map.put(db.documents, doc.id, doc)
    user_documents = Map.put(db.user_documents, user_document.id, user_document)
    updated_db = %__MODULE__{db | documents: documents, user_documents: user_documents}
    {:ok, doc, updated_db}
  end

  @spec share_user_document(
          db :: Database.t(),
          from_user :: User.t(),
          to_user :: User.t(),
          document :: EncryptedDocument.t(),
          password :: binary
        ) ::
          {:error, binary | :failed_verification}
          | {:ok, Database.t()}
  def share_user_document(
        %__MODULE__{} = db,
        %User{} = from_user,
        %User{} = to_user,
        %EncryptedDocument{} = document,
        password
      ) do
    user_doc_id = "#{from_user.username}-#{document.id}"

    case Map.get(db.user_documents, user_doc_id) do
      %{user_key: user_document_key} ->
        with {:ok, user_key} <-
               Utils.decrypt_key_hash(password, from_user.key_hash),
             {:ok, priv_key} <-
               Utils.decrypt(%{
                 key: user_key,
                 payload: from_user.key_pair.private_hash
               }),
             {:ok, document_key} <-
               Utils.decrypt_message_for_user(
                 user_document_key,
                 %{public: from_user.key_pair.public, private: priv_key}
               ) do
          user_document = UserDocument.new(to_user, document, document_key)
          user_documents = Map.put(db.user_documents, user_document.id, user_document)
          {:ok, %__MODULE__{db | user_documents: user_documents}}
        else
          e -> {:error, e}
        end

      _ ->
        {:error, "Invalid user"}
    end
  end
end

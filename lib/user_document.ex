defmodule UserEncryption.UserDocument do
  defstruct id: nil, user_key: nil

  @type t :: %__MODULE__{
          id: String.t(),
          user_key: String.t()
        }
  alias UserEncryption.User
  alias UserEncryption.EncryptedDocument
  alias UserEncryption.KeyPair
  alias UserEncryption.Utils
  alias UserEncryption.UserDocument

  @spec new(User.t(), EncryptedDocument.t(), binary) :: UserDocument.t()
  def new(
        %User{key_pair: %KeyPair{public: public}} = user,
        %EncryptedDocument{} = document,
        document_key
      ) do
    id = "#{user.username}-#{document.id}"

    user_key =
      Utils.encrypt_message_for_user_with_pk(document_key, %{
        public: public
      })

    struct!(__MODULE__, id: id, user_key: user_key)
  end
end

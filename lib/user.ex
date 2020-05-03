defmodule UserEncryption.User do
  defstruct username: nil, key_hash: nil, key_pair: nil

  alias UserEncryption.KeyPair

  @type t :: %__MODULE__{
          username: String.t(),
          key_hash: String.t(),
          key_pair: UserEncryption.KeyPair.t()
        }

  alias UserEncryption.Utils
  alias UserEncryption.User

  @spec new(username :: binary, password :: binary) :: User.t()
  def new(username, password) do
    user_key = Utils.generate_key()
    %{key_hash: key_hash} = Utils.generate_key_hash(password, user_key)

    %{public: pub, private: priv_key} = Utils.generate_key_pairs()

    encrypted_priv_key = Utils.encrypt(%{key: user_key, payload: priv_key})

    %__MODULE__{
      key_hash: key_hash,
      username: username,
      key_pair: %KeyPair{public: pub, private_hash: encrypted_priv_key}
    }
  end
end

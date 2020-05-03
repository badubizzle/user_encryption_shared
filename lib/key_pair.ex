defmodule UserEncryption.KeyPair do
  defstruct public: nil, private_hash: nil

  @type t :: %__MODULE__{
          public: String.t(),
          private_hash: String.t()
        }
  alias UserEncryption.Utils
  alias UserEncryption.KeyPair

  @spec new(binary) :: KeyPair.t()
  def new(user_key) do
    %{public: pub, private: priv_key} = Utils.generate_key_pairs()
    encrypted_priv_key = Utils.encrypt(%{key: user_key, payload: priv_key})
    struct!(__MODULE__, public: pub, private_hash: encrypted_priv_key)
  end
end

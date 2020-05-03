defmodule UserEncryption.EncryptedDocument do
  defstruct id: nil, data_hash: nil

  @type t :: %__MODULE__{
          id: String.t(),
          data_hash: String.t()
        }
  alias UserEncryption.Utils

  @spec new(content :: binary, key :: binary, id :: binary | nil) ::
          EncryptedDocument.t()
  def new(content, key, id \\ nil) do
    doc_id =
      if is_nil(id) do
        Utils.generate_key()
      else
        id
      end

    data_hash = Utils.encrypt(%{key: key, payload: content})
    %__MODULE__{data_hash: data_hash, id: doc_id}
  end

  @spec new(binary) :: EncryptedDocument.t()
  def new(content) do
    key = Utils.generate_key()
    new(content, key)
  end
end

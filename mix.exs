defmodule UserEncryption.MixProject do
  use Mix.Project

  def project do
    [
      app: :user_encryption,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:enacl, git: "https://github.com/jlouis/enacl"}
    ]
  end
end

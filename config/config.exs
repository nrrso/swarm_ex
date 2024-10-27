# File: swarm_ex/config/config.exs

import Config

config :swarm_ex,
  default_timeout: 5_000,
  max_retries: 3

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"

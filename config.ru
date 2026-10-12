# This file is used by Rack-based servers to start the application.

require_relative "config/environment"

# Serve the app below RAILS_RELATIVE_URL_ROOT (e.g. /watch) so generated links carry the prefix.
# Works whether Nginx strips the prefix before proxying or passes it through.
class MountAtRelativeUrlRoot
  def initialize(app, relative_url_root)
    @app = app
    @relative_url_root = relative_url_root.to_s.delete_suffix("/")
  end

  def call(env)
    path_info = env["PATH_INFO"].to_s
    if path_info == @relative_url_root || path_info.start_with?("#{@relative_url_root}/")
      env["PATH_INFO"] = path_info.delete_prefix(@relative_url_root).presence || "/"
    end
    env["SCRIPT_NAME"] = @relative_url_root

    @app.call(env)
  end
end

relative_url_root = Rails.application.config.relative_url_root
use MountAtRelativeUrlRoot, relative_url_root if relative_url_root.present?
run Rails.application

Rails.application.load_server

class ApplicationMailer < ActionMailer::Base
  default from: -> { ENV.fetch("MAIL_FROM", "vuln-watch@example.com") }
  layout "mailer"
end

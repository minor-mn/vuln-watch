class EmergencyMailer < ApplicationMailer
  helper :cves

  def self.recipients
    ENV.fetch("MAIL_TO", "").split(",").map(&:strip).reject(&:blank?)
  end

  def emergency
    @notification = params[:notification]
    @cve = @notification.cve
    @judgement = @notification.judgement
    @analysis = @judgement.ai_analysis
    products = @cve.product_matches.map(&:product_name).uniq.join(", ")

    mail to: self.class.recipients, subject: "[緊急] #{@cve.identifier} #{products}".strip
  end
end

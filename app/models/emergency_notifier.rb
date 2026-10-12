# Sends the emergency email: a one-off flash that the CVE met the emergency conditions at least
# once. One email per CVE, only for matched CVEs (never possible_match). Later changes of the
# judgement are shown on the site, not mailed.
class EmergencyNotifier
  def initialize(logger: Rails.logger)
    @logger = logger
  end

  def notify(cve)
    return unless cve.matched? && cve.judged_emergency?
    return if cve.notification&.sent_at

    if EmergencyMailer.recipients.empty?
      @logger.warn("[notifier] MAIL_TO is not set; not notifying #{cve.identifier}")
      return
    end

    # The unique index on cve_id keeps two workers from both creating the record.
    notification = Notification.create_or_find_by!(cve:) { |n| n.judgement = cve.latest_judgement }
    return if notification.sent_at

    EmergencyMailer.with(notification:).emergency.deliver_now
    notification.update!(sent_at: Time.current)
  end
end

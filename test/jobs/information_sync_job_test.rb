require "test_helper"

class InformationSyncJobTest < ActiveJob::TestCase
  test "hourly coordinator only enqueues enabled sources and permits all disabled" do
    previous = ENV["INFORMATION_SOURCES"]
    ENV["INFORMATION_SOURCES"] = "cve,slashdot"
    assert_enqueued_jobs 2, only: InformationSourceSyncJob do
      InformationSyncJob.perform_now
    end
    assert_enqueued_with(job: InformationSourceSyncJob, args: [ "cve" ])
    assert_enqueued_with(job: InformationSourceSyncJob, args: [ "slashdot" ])
    ENV["INFORMATION_SOURCES"] = ""
    assert_no_enqueued_jobs { InformationSyncJob.perform_now }
  ensure
    ENV["INFORMATION_SOURCES"] = previous
  end

  test "disabled source cannot be run by an older queued job" do
    previous = ENV["INFORMATION_SOURCES"]
    ENV["INFORMATION_SOURCES"] = ""
    assert_no_difference "InformationSourceState.count" do
      InformationSourceSyncJob.perform_now("slashdot")
    end
  ensure
    ENV["INFORMATION_SOURCES"] = previous
  end

  test "rate limited sources wait until the stored retry time" do
    state = InformationSourceState.create!(source: "slashdot", retry_at: 4.hours.from_now)
    InformationSourceSyncJob.perform_now("slashdot")
    assert_nil state.reload.attempted_at
  end

  test "a failed update keeps earlier success and exposes rate limit retry time" do
    state = InformationSourceState.create!(source: "slashdot", succeeded_at: 1.hour.ago)
    previous_success = state.succeeded_at
    retry_at = 3.hours.from_now
    job = InformationSourceSyncJob.new
    job.define_singleton_method(:synchronize) { |source| raise InformationHttp::Error.new("HTTP 429", retry_at:) }
    assert_raises(InformationHttp::Error) { job.perform("slashdot") }
    assert_equal previous_success, state.reload.succeeded_at
    assert_equal retry_at.to_i, state.retry_at.to_i
    assert_equal "HTTP 429", state.error_message
    assert state.attempted_at
  end
end

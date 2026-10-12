require "test_helper"

class CvelistSynchronizerTest < ActiveSupport::TestCase
  setup do
    @dir = Pathname(Dir.mktmpdir("cvelist"))
    @origin = @dir.join("origin")
    git_origin("init", "--quiet", "--initial-branch", "main")
    git_origin("config", "user.email", "test@example.com")
    git_origin("config", "user.name", "test")
    git_origin("config", "uploadpack.allowFilter", "true")
    git_origin("config", "uploadpack.allowAnySHA1InWant", "true")

    # file:// so that --depth and --filter are honored for a local origin
    @repository = Cvelist::Repository.new(path: @dir.join("clone").to_s, url: "file://#{@origin}")
    @synchronizer = CvelistSynchronizer.new(repository: @repository, matcher: ProductMatcher.new(sample_products),
      logger: Logger.new(nil))
  end

  teardown { FileUtils.rm_rf(@dir) }

  test "the first run ingests CVEs published in the last month" do
    commit_cve(cve_json(id: "CVE-2026-0001", published: 3.months.ago.iso8601), at: 3.months.ago)
    # The real repository commits every few minutes; this one becomes the oldest fetched commit.
    commit_cve(cve_json(id: "CVE-2026-0009", vendor: "acme", product: "widget"), at: 1.month.ago - 12.hours)
    commit_cve(cve_json(id: "CVE-2026-0002", published: 20.days.ago.iso8601), at: 20.days.ago)
    commit_cve(cve_json(id: "CVE-2026-0003", published: 10.days.ago.iso8601), at: 10.days.ago)
    commit_cve(cve_json(id: "CVE-2026-0001", published: 3.months.ago.iso8601, updated: 1.day.ago.iso8601), at: 1.day.ago)

    results = @synchronizer.call

    assert_equal %w[CVE-2026-0002 CVE-2026-0003], results.map { |r| r.cve.identifier }.sort
    assert_equal 3, CvelistSync.last_succeeded.changed_files_count
  end

  test "later runs ingest only files changed since the last sync" do
    commit_cve(cve_json(id: "CVE-2026-0001", published: 3.months.ago.iso8601), at: 3.months.ago)
    commit_cve(cve_json(id: "CVE-2026-0004", vendor: "acme", product: "widget"), at: 10.days.ago)
    @synchronizer.call
    first_sync = CvelistSync.last_succeeded

    commit_cve(cve_json(id: "CVE-2026-0001", published: 3.months.ago.iso8601, updated: Time.current.iso8601))
    commit_cve(cve_json(id: "CVE-2026-0002", vendor: "n/a", product: "PostgreSQL", published: Time.current.iso8601))
    commit_cve(cve_json(id: "CVE-2026-0003", vendor: "acme", product: "widget", published: Time.current.iso8601))
    results = @synchronizer.call

    assert_equal [ "CVE-2026-0002" ], results.map { |r| r.cve.identifier }
    assert_equal first_sync.to_commit, CvelistSync.last_succeeded.from_commit
    assert_equal 3, CvelistSync.last_succeeded.changed_files_count
  end

  test "does not download contents of files older than the look-back" do
    commit_cve(cve_json(id: "CVE-2026-0001"), at: 3.months.ago)
    commit_cve(cve_json(id: "CVE-2026-0002", vendor: "acme", product: "widget"), at: 10.days.ago)
    @synchronizer.call

    missing = Open3.capture2("git", "rev-list", "--objects", "--all", "--missing=print", chdir: @repository.path.to_s)
      .first.lines.grep(/\A\?/)
    assert_not_empty missing
  end

  test "records a failed sync" do
    repository = Cvelist::Repository.new(path: @dir.join("clone").to_s, url: "file://#{@dir.join('missing')}")
    synchronizer = CvelistSynchronizer.new(repository:, matcher: ProductMatcher.new(sample_products), logger: Logger.new(nil))

    assert_raises(Cvelist::Repository::GitError) { synchronizer.call }
    assert CvelistSync.last.failed?
  end

  private
    def commit_cve(json, at: Time.current)
      id = json.dig("cveMetadata", "cveId")
      year, number = id.split("-").values_at(1, 2)
      file = @origin.join("cves", year, "#{number[0..-4]}xxx", "#{id}.json")
      FileUtils.mkdir_p(file.dirname)
      file.write(JSON.pretty_generate(json))
      git_origin("add", ".")
      git_origin("commit", "--quiet", "-m", id, env: { "GIT_AUTHOR_DATE" => at.iso8601, "GIT_COMMITTER_DATE" => at.iso8601 })
    end

    def git_origin(*args, env: {})
      FileUtils.mkdir_p(@origin)
      _, stderr, status = Open3.capture3(env, "git", *args, chdir: @origin.to_s)
      raise stderr unless status.success?
    end
end

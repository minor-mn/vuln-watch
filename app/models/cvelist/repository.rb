require "open3"

# Minimal local clone of CVEProject/cvelistV5.
#
# Only recent commits and their trees are fetched (--depth 1 or --shallow-since, --filter=blob:none,
# no checkout), so past CVE files are never downloaded. File contents are fetched only when read.
class Cvelist::Repository
  class GitError < StandardError; end

  BRANCH = "main".freeze
  EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904".freeze
  PREFETCH_BATCH_SIZE = 500
  CVE_FILE_PATTERN = %r{\Acves/\d{4}/[^/]+/CVE-\d{4}-\d+\.json\z}

  attr_reader :path, :url

  def initialize(path: ENV.fetch("CVELIST_PATH", "vendor/cvelist"),
                 url: ENV.fetch("CVELIST_REPO_URL", "https://github.com/CVEProject/cvelistV5.git"))
    @path = Rails.root.join(path)
    @url = url
  end

  def cloned?
    path.join(".git").directory?
  end

  # since: also fetch the commits made after this time (for the first sync's look-back).
  def clone!(since: nil)
    FileUtils.mkdir_p(path.dirname)
    run("git", "clone", "--quiet", *history_option(since), "--filter=blob:none", "--no-checkout",
      "--single-branch", "--branch", BRANCH, url, path.to_s, chdir: Rails.root)
  end

  def fetch!(since: nil)
    git("fetch", "--quiet", *history_option(since), "origin", BRANCH)
  end

  # The oldest commit available locally.
  def oldest_commit
    git("rev-list", "--reverse", "origin/#{BRANCH}").lines(chomp: true).first
  end

  def remote_head
    git("rev-parse", "origin/#{BRANCH}").strip
  end

  # Makes sure a previously seen commit is still available locally.
  def ensure_commit!(commit)
    git("cat-file", "-e", "#{commit}^{commit}")
  rescue GitError
    git("fetch", "--quiet", "--depth", "1", "origin", commit)
  end

  # CVE files added or modified between two commits.
  def changed_cve_files(from, to)
    git("diff", "--name-only", "--diff-filter=AM", "--no-renames", from, to)
      .lines(chomp: true).grep(CVE_FILE_PATTERN)
  end

  def read(commit, file)
    git("show", "#{commit}:#{file}")
  end

  # Downloads the contents of many files in a few requests instead of one per file.
  # Diffing against the empty tree makes git batch-fetch the missing blobs it needs.
  def prefetch!(commit, files)
    files.each_slice(PREFETCH_BATCH_SIZE) do |batch|
      git("diff", "--numstat", EMPTY_TREE, commit, "--", *batch)
    end
  end

  private
    def history_option(since)
      since ? [ "--shallow-since=#{since.iso8601}" ] : [ "--depth", "1" ]
    end

    def git(*args)
      run("git", *args, chdir: path)
    end

    def run(*command, chdir:)
      stdout, stderr, status = Open3.capture3(*command, chdir: chdir.to_s)
      raise GitError, "#{command.join(' ')}: #{stderr.strip}" unless status.success?

      stdout
    end
end

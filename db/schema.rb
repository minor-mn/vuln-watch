# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_10_18_000001) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "ai_analyses", force: :cascade do |t|
    t.bigint "cve_id", null: false
    t.string "input_hash", null: false
    t.jsonb "input", null: false
    t.string "model", null: false
    t.string "prompt_version", null: false
    t.datetime "analyzed_at", null: false
    t.string "remote_code_execution", null: false
    t.string "authentication_bypass", null: false
    t.string "shell_access", null: false
    t.string "root_access", null: false
    t.jsonb "evidence", default: [], null: false
    t.text "summary_overview"
    t.text "summary_impact"
    t.text "summary_affected"
    t.text "summary_mitigation"
    t.jsonb "raw_response", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["cve_id", "input_hash", "model", "prompt_version"], name: "index_ai_analyses_uniqueness", unique: true
    t.index ["cve_id"], name: "index_ai_analyses_on_cve_id"
  end

  create_table "cve_snapshots", force: :cascade do |t|
    t.bigint "cve_id", null: false
    t.bigint "cvelist_sync_id"
    t.jsonb "raw_json", null: false
    t.datetime "record_date_updated", null: false
    t.string "git_commit"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["cve_id", "record_date_updated"], name: "index_cve_snapshots_on_cve_id_and_record_date_updated", unique: true
    t.index ["cve_id"], name: "index_cve_snapshots_on_cve_id"
    t.index ["cvelist_sync_id"], name: "index_cve_snapshots_on_cvelist_sync_id"
  end

  create_table "cvelist_syncs", force: :cascade do |t|
    t.string "from_commit"
    t.string "to_commit"
    t.string "status", default: "running", null: false
    t.integer "changed_files_count", default: 0, null: false
    t.integer "matched_cves_count", default: 0, null: false
    t.text "error_message"
    t.datetime "started_at", null: false
    t.datetime "finished_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["status"], name: "index_cvelist_syncs_on_status"
  end

  create_table "cves", force: :cascade do |t|
    t.string "identifier", null: false
    t.string "state", null: false
    t.datetime "date_published"
    t.datetime "record_date_updated"
    t.string "match_status", null: false
    t.string "current_judgement", default: "unknown", null: false
    t.boolean "assessment_mismatch", default: false, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["current_judgement"], name: "index_cves_on_current_judgement"
    t.index ["date_published"], name: "index_cves_on_date_published"
    t.index ["identifier"], name: "index_cves_on_identifier", unique: true
    t.index ["match_status"], name: "index_cves_on_match_status"
  end

  create_table "cvss_assessments", force: :cascade do |t|
    t.bigint "source_revision_id", null: false
    t.string "version", null: false
    t.string "attack_vector", null: false
    t.string "privileges_required", null: false
    t.string "user_interaction", null: false
    t.string "vector_string", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["source_revision_id", "version"], name: "index_cvss_assessments_on_source_revision_id_and_version", unique: true
    t.index ["source_revision_id"], name: "index_cvss_assessments_on_source_revision_id"
  end

  create_table "information_items", force: :cascade do |t|
    t.string "source", null: false
    t.string "url", null: false
    t.text "title", null: false
    t.text "body", default: "", null: false
    t.datetime "published_at", null: false
    t.datetime "fetched_at", null: false
    t.text "summary"
    t.boolean "relevant"
    t.boolean "listed", default: true, null: false
    t.string "summary_digest"
    t.jsonb "details", default: {}, null: false
    t.jsonb "thread", default: {}, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["source", "listed", "published_at"], name: "index_information_items_on_source_and_listed_and_published_at"
    t.index ["source", "url"], name: "index_information_items_on_source_and_url", unique: true
  end

  create_table "information_source_states", force: :cascade do |t|
    t.string "source", null: false
    t.datetime "attempted_at"
    t.datetime "succeeded_at"
    t.datetime "retry_at"
    t.text "error_message"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["source"], name: "index_information_source_states_on_source", unique: true
  end

  create_table "judgements", force: :cascade do |t|
    t.bigint "cve_id", null: false
    t.string "result", null: false
    t.string "attack_condition", null: false
    t.string "capability_condition", null: false
    t.bigint "selected_assessment_id"
    t.bigint "ai_analysis_id"
    t.datetime "effective_at", null: false
    t.jsonb "changes_summary", default: [], null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["ai_analysis_id"], name: "index_judgements_on_ai_analysis_id"
    t.index ["cve_id", "effective_at"], name: "index_judgements_on_cve_id_and_effective_at"
    t.index ["cve_id"], name: "index_judgements_on_cve_id"
    t.index ["selected_assessment_id"], name: "index_judgements_on_selected_assessment_id"
  end

  create_table "notifications", force: :cascade do |t|
    t.bigint "cve_id", null: false
    t.bigint "judgement_id", null: false
    t.datetime "sent_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["cve_id"], name: "index_notifications_on_cve_id", unique: true
    t.index ["judgement_id"], name: "index_notifications_on_judgement_id"
  end

  create_table "product_matches", force: :cascade do |t|
    t.bigint "cve_id", null: false
    t.string "product_name", null: false
    t.string "rule", null: false
    t.string "matched_term", null: false
    t.string "matched_text", null: false
    t.string "ai_affects_product"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["cve_id", "product_name", "rule"], name: "index_product_matches_on_cve_id_and_product_name_and_rule", unique: true
    t.index ["cve_id"], name: "index_product_matches_on_cve_id"
  end

  create_table "source_revisions", force: :cascade do |t|
    t.bigint "cve_id", null: false
    t.bigint "cve_snapshot_id", null: false
    t.string "source", null: false
    t.datetime "source_date_updated", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["cve_id", "source", "source_date_updated"], name: "index_source_revisions_uniqueness", unique: true
    t.index ["cve_id"], name: "index_source_revisions_on_cve_id"
    t.index ["cve_snapshot_id"], name: "index_source_revisions_on_cve_snapshot_id"
  end

  add_foreign_key "ai_analyses", "cves"
  add_foreign_key "cve_snapshots", "cvelist_syncs"
  add_foreign_key "cve_snapshots", "cves"
  add_foreign_key "cvss_assessments", "source_revisions"
  add_foreign_key "judgements", "ai_analyses"
  add_foreign_key "judgements", "cves"
  add_foreign_key "judgements", "cvss_assessments", column: "selected_assessment_id"
  add_foreign_key "notifications", "cves"
  add_foreign_key "notifications", "judgements"
  add_foreign_key "product_matches", "cves"
  add_foreign_key "source_revisions", "cve_snapshots"
  add_foreign_key "source_revisions", "cves"
end

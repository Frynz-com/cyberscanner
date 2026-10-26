
export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[]

export type Database = {
  
  "graphql_public": {
          Tables: {
            [_ in never]: never
          }
          Views: {
            [_ in never]: never
          }
          Functions: {
            "graphql":
{ Args: { "extensions"?: Json,"operationName"?: string,"query"?: string,"variables"?: Json }; Returns: Json
                           }
          }
          Enums: {
            [_ in never]: never
          }
          CompositeTypes: {
            [_ in never]: never
          }
        },"public": {
          Tables: {
            "actions": {
                  Row: {
                    "created_at": string,"created_by": string | null,"finding_id": string,"id": string,"invite_id": string | null,"note": string | null,"org_id": string,"status": string,"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"created_by"?: string | null,"finding_id": string,"id"?: string,"invite_id"?: string | null,"note"?: string | null,"org_id": string,"status"?: string,"updated_at"?: string
                  }
                  Update: {
                    "created_at"?: string,"created_by"?: string | null,"finding_id"?: string,"id"?: string,"invite_id"?: string | null,"note"?: string | null,"org_id"?: string,"status"?: string,"updated_at"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "actions_finding_id_fkey"
      columns: ["finding_id"]
isOneToOne: false
      referencedRelation: "findings"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "actions_invite_id_fkey"
      columns: ["invite_id"]
isOneToOne: false
      referencedRelation: "service_provider_invites"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "actions_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"assets": {
                  Row: {
                    "domain_id": string,"first_seen_at": string,"id": string,"is_active": boolean,"is_demo": boolean,"kind": string,"last_seen_at": string,"metadata": NonNullable<Json>,"org_id": string,"sources": (string)[],"value": string,"vuln_scan_approved": boolean
                  }
                  ComputedFields: never
                  Insert: {
                    "domain_id": string,"first_seen_at"?: string,"id"?: string,"is_active"?: boolean,"is_demo"?: boolean,"kind": string,"last_seen_at"?: string,"metadata"?: NonNullable<Json>,"org_id": string,"sources"?: (string)[],"value": string,"vuln_scan_approved"?: boolean
                  }
                  Update: {
                    "domain_id"?: string,"first_seen_at"?: string,"id"?: string,"is_active"?: boolean,"is_demo"?: boolean,"kind"?: string,"last_seen_at"?: string,"metadata"?: NonNullable<Json>,"org_id"?: string,"sources"?: (string)[],"value"?: string,"vuln_scan_approved"?: boolean
                  }
                  Relationships: [
                    {
      foreignKeyName: "assets_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "assets_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"audit_logs": {
                  Row: {
                    "action": string,"actor_id": string | null,"actor_type": string,"created_at": string,"data": NonNullable<Json>,"id": number,"ip_hash": string | null,"org_id": string | null,"target_id": string | null,"target_type": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "action": string,"actor_id"?: string | null,"actor_type": string,"created_at"?: string,"data"?: NonNullable<Json>,"id"?: never,"ip_hash"?: string | null,"org_id"?: string | null,"target_id"?: string | null,"target_type"?: string | null
                  }
                  Update: {
                    "action"?: string,"actor_id"?: string | null,"actor_type"?: string,"created_at"?: string,"data"?: NonNullable<Json>,"id"?: never,"ip_hash"?: string | null,"org_id"?: string | null,"target_id"?: string | null,"target_type"?: string | null
                  }
                  Relationships: [
                    {
      foreignKeyName: "audit_logs_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"breach_records": {
                  Row: {
                    "account_enc": string,"account_hmac": string,"breach_added_at": string | null,"breach_date": string | null,"breach_key": string,"breach_title": string | null,"data_classes": (string)[],"domain_id": string,"finding_id": string | null,"first_observed_at": string,"id": string,"is_stealer_log": boolean,"is_synthetic": boolean,"last_observed_at": string,"org_id": string,"provider": string
                  }
                  ComputedFields: never
                  Insert: {
                    "account_enc": string,"account_hmac": string,"breach_added_at"?: string | null,"breach_date"?: string | null,"breach_key": string,"breach_title"?: string | null,"data_classes"?: (string)[],"domain_id": string,"finding_id"?: string | null,"first_observed_at"?: string,"id"?: string,"is_stealer_log"?: boolean,"is_synthetic"?: boolean,"last_observed_at"?: string,"org_id": string,"provider": string
                  }
                  Update: {
                    "account_enc"?: string,"account_hmac"?: string,"breach_added_at"?: string | null,"breach_date"?: string | null,"breach_key"?: string,"breach_title"?: string | null,"data_classes"?: (string)[],"domain_id"?: string,"finding_id"?: string | null,"first_observed_at"?: string,"id"?: string,"is_stealer_log"?: boolean,"is_synthetic"?: boolean,"last_observed_at"?: string,"org_id"?: string,"provider"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "breach_records_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "breach_records_finding_id_fkey"
      columns: ["finding_id"]
isOneToOne: false
      referencedRelation: "findings"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "breach_records_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"cve_kev": {
                  Row: {
                    "cve_id": string,"date_added": string | null,"known_ransomware": boolean,"name": string | null,"product": string | null,"vendor": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "cve_id": string,"date_added"?: string | null,"known_ransomware"?: boolean,"name"?: string | null,"product"?: string | null,"vendor"?: string | null
                  }
                  Update: {
                    "cve_id"?: string,"date_added"?: string | null,"known_ransomware"?: boolean,"name"?: string | null,"product"?: string | null,"vendor"?: string | null
                  }
                  Relationships: [
                    
                  ]
                },"domains": {
                  Row: {
                    "created_at": string,"created_by": string | null,"hostname": string,"id": string,"is_demo": boolean,"last_scan_at": string | null,"monitoring_enabled": boolean,"next_intel_at": string | null,"next_scan_at": string | null,"org_id": string,"scan_interval_hours": number,"verification_last_checked_at": string | null,"verification_status": Database["public"]['Enums']["domain_verification_status"],"verified_at": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"created_by"?: string | null,"hostname": string,"id"?: string,"is_demo"?: boolean,"last_scan_at"?: string | null,"monitoring_enabled"?: boolean,"next_intel_at"?: string | null,"next_scan_at"?: string | null,"org_id": string,"scan_interval_hours"?: number,"verification_last_checked_at"?: string | null,"verification_status"?: Database["public"]['Enums']["domain_verification_status"],"verified_at"?: string | null
                  }
                  Update: {
                    "created_at"?: string,"created_by"?: string | null,"hostname"?: string,"id"?: string,"is_demo"?: boolean,"last_scan_at"?: string | null,"monitoring_enabled"?: boolean,"next_intel_at"?: string | null,"next_scan_at"?: string | null,"org_id"?: string,"scan_interval_hours"?: number,"verification_last_checked_at"?: string | null,"verification_status"?: Database["public"]['Enums']["domain_verification_status"],"verified_at"?: string | null
                  }
                  Relationships: [
                    {
      foreignKeyName: "domains_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"finding_events": {
                  Row: {
                    "actor_id": string | null,"actor_label": string | null,"actor_type": string,"created_at": string,"data": NonNullable<Json>,"finding_id": string,"from_status": Database["public"]['Enums']["finding_status"] | null,"id": string,"message": string | null,"org_id": string,"to_status": Database["public"]['Enums']["finding_status"] | null,"type": string
                  }
                  ComputedFields: never
                  Insert: {
                    "actor_id"?: string | null,"actor_label"?: string | null,"actor_type": string,"created_at"?: string,"data"?: NonNullable<Json>,"finding_id": string,"from_status"?: Database["public"]['Enums']["finding_status"] | null,"id"?: string,"message"?: string | null,"org_id": string,"to_status"?: Database["public"]['Enums']["finding_status"] | null,"type": string
                  }
                  Update: {
                    "actor_id"?: string | null,"actor_label"?: string | null,"actor_type"?: string,"created_at"?: string,"data"?: NonNullable<Json>,"finding_id"?: string,"from_status"?: Database["public"]['Enums']["finding_status"] | null,"id"?: string,"message"?: string | null,"org_id"?: string,"to_status"?: Database["public"]['Enums']["finding_status"] | null,"type"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "finding_events_finding_id_fkey"
      columns: ["finding_id"]
isOneToOne: false
      referencedRelation: "findings"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "finding_events_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"findings": {
                  Row: {
                    "asset_id": string | null,"asset_value": string,"business_impact": string,"category": string,"certainty": Database["public"]['Enums']["finding_certainty"],"check_key": string,"confidence": Database["public"]['Enums']["confidence_level"],"created_at": string,"docs": NonNullable<Json>,"domain_id": string | null,"evidence": NonNullable<Json>,"fingerprint": string,"first_seen_at": string,"id": string,"is_demo": boolean,"last_job_id": string | null,"last_seen_at": string,"org_id": string,"priority_reasons": NonNullable<Json>,"priority_score": number,"recommendation": string,"reopened_count": number,"resolved_at": string | null,"rule_id": string,"severity": Database["public"]['Enums']["finding_severity"],"source": string,"source_ref": string | null,"status": Database["public"]['Enums']["finding_status"],"summary": string,"technical_details": string,"title": string,"updated_at": string,"verification_state": string | null,"verification_steps": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "asset_id"?: string | null,"asset_value": string,"business_impact": string,"category": string,"certainty": Database["public"]['Enums']["finding_certainty"],"check_key": string,"confidence": Database["public"]['Enums']["confidence_level"],"created_at"?: string,"docs"?: NonNullable<Json>,"domain_id"?: string | null,"evidence"?: NonNullable<Json>,"fingerprint": string,"first_seen_at"?: string,"id"?: string,"is_demo"?: boolean,"last_job_id"?: string | null,"last_seen_at"?: string,"org_id": string,"priority_reasons"?: NonNullable<Json>,"priority_score"?: number,"recommendation": string,"reopened_count"?: number,"resolved_at"?: string | null,"rule_id": string,"severity": Database["public"]['Enums']["finding_severity"],"source": string,"source_ref"?: string | null,"status"?: Database["public"]['Enums']["finding_status"],"summary": string,"technical_details": string,"title": string,"updated_at"?: string,"verification_state"?: string | null,"verification_steps"?: string | null
                  }
                  Update: {
                    "asset_id"?: string | null,"asset_value"?: string,"business_impact"?: string,"category"?: string,"certainty"?: Database["public"]['Enums']["finding_certainty"],"check_key"?: string,"confidence"?: Database["public"]['Enums']["confidence_level"],"created_at"?: string,"docs"?: NonNullable<Json>,"domain_id"?: string | null,"evidence"?: NonNullable<Json>,"fingerprint"?: string,"first_seen_at"?: string,"id"?: string,"is_demo"?: boolean,"last_job_id"?: string | null,"last_seen_at"?: string,"org_id"?: string,"priority_reasons"?: NonNullable<Json>,"priority_score"?: number,"recommendation"?: string,"reopened_count"?: number,"resolved_at"?: string | null,"rule_id"?: string,"severity"?: Database["public"]['Enums']["finding_severity"],"source"?: string,"source_ref"?: string | null,"status"?: Database["public"]['Enums']["finding_status"],"summary"?: string,"technical_details"?: string,"title"?: string,"updated_at"?: string,"verification_state"?: string | null,"verification_steps"?: string | null
                  }
                  Relationships: [
                    {
      foreignKeyName: "findings_asset_id_fkey"
      columns: ["asset_id"]
isOneToOne: false
      referencedRelation: "assets"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "findings_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "findings_last_job_id_fkey"
      columns: ["last_job_id"]
isOneToOne: false
      referencedRelation: "scan_jobs"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "findings_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"incident_events": {
                  Row: {
                    "actor_id": string | null,"actor_label": string | null,"created_at": string,"data": NonNullable<Json>,"id": string,"incident_id": string,"message": string | null,"org_id": string,"type": string
                  }
                  ComputedFields: never
                  Insert: {
                    "actor_id"?: string | null,"actor_label"?: string | null,"created_at"?: string,"data"?: NonNullable<Json>,"id"?: string,"incident_id": string,"message"?: string | null,"org_id": string,"type": string
                  }
                  Update: {
                    "actor_id"?: string | null,"actor_label"?: string | null,"created_at"?: string,"data"?: NonNullable<Json>,"id"?: string,"incident_id"?: string,"message"?: string | null,"org_id"?: string,"type"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "incident_events_incident_id_fkey"
      columns: ["incident_id"]
isOneToOne: false
      referencedRelation: "incidents"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "incident_events_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"incident_files": {
                  Row: {
                    "content_type": string,"created_at": string,"file_name": string,"id": string,"incident_id": string,"org_id": string,"sha256": string,"size_bytes": number,"storage_path": string,"uploaded_by": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "content_type": string,"created_at"?: string,"file_name": string,"id"?: string,"incident_id": string,"org_id": string,"sha256": string,"size_bytes": number,"storage_path": string,"uploaded_by"?: string | null
                  }
                  Update: {
                    "content_type"?: string,"created_at"?: string,"file_name"?: string,"id"?: string,"incident_id"?: string,"org_id"?: string,"sha256"?: string,"size_bytes"?: number,"storage_path"?: string,"uploaded_by"?: string | null
                  }
                  Relationships: [
                    {
      foreignKeyName: "incident_files_incident_id_fkey"
      columns: ["incident_id"]
isOneToOne: false
      referencedRelation: "incidents"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "incident_files_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"incidents": {
                  Row: {
                    "assigned_contact": string | null,"closed_at": string | null,"created_at": string,"description": string | null,"id": string,"is_demo": boolean,"org_id": string,"priority": string,"reported_by": string | null,"reporter_name": string | null,"reporter_phone": string | null,"status": string,"title": string,"type": string,"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "assigned_contact"?: string | null,"closed_at"?: string | null,"created_at"?: string,"description"?: string | null,"id"?: string,"is_demo"?: boolean,"org_id": string,"priority": string,"reported_by"?: string | null,"reporter_name"?: string | null,"reporter_phone"?: string | null,"status"?: string,"title": string,"type": string,"updated_at"?: string
                  }
                  Update: {
                    "assigned_contact"?: string | null,"closed_at"?: string | null,"created_at"?: string,"description"?: string | null,"id"?: string,"is_demo"?: boolean,"org_id"?: string,"priority"?: string,"reported_by"?: string | null,"reporter_name"?: string | null,"reporter_phone"?: string | null,"status"?: string,"title"?: string,"type"?: string,"updated_at"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "incidents_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"leads": {
                  Row: {
                    "company": string | null,"consent_at": string,"consent_text": string,"created_at": string,"email": string,"hostname": string | null,"id": string,"public_check_id": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "company"?: string | null,"consent_at"?: string,"consent_text": string,"created_at"?: string,"email": string,"hostname"?: string | null,"id"?: string,"public_check_id"?: string | null
                  }
                  Update: {
                    "company"?: string | null,"consent_at"?: string,"consent_text"?: string,"created_at"?: string,"email"?: string,"hostname"?: string | null,"id"?: string,"public_check_id"?: string | null
                  }
                  Relationships: [
                    {
      foreignKeyName: "leads_public_check_id_fkey"
      columns: ["public_check_id"]
isOneToOne: false
      referencedRelation: "public_checks"
      referencedColumns: ["id"]
    }
                  ]
                },"memberships": {
                  Row: {
                    "created_at": string,"org_id": string,"role": string,"user_id": string
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"org_id": string,"role": string,"user_id": string
                  }
                  Update: {
                    "created_at"?: string,"org_id"?: string,"role"?: string,"user_id"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "memberships_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "memberships_role_fkey"
      columns: ["role"]
isOneToOne: false
      referencedRelation: "roles"
      referencedColumns: ["key"]
    }
                  ]
                },"notifications": {
                  Row: {
                    "body": string,"created_at": string,"dedupe_key": string,"email_attempts": number,"email_error": string | null,"email_sent_at": string | null,"email_status": string,"id": string,"link": string | null,"org_id": string,"read_at": string | null,"severity": string,"title": string,"type": string
                  }
                  ComputedFields: never
                  Insert: {
                    "body": string,"created_at"?: string,"dedupe_key": string,"email_attempts"?: number,"email_error"?: string | null,"email_sent_at"?: string | null,"email_status"?: string,"id"?: string,"link"?: string | null,"org_id": string,"read_at"?: string | null,"severity"?: string,"title": string,"type": string
                  }
                  Update: {
                    "body"?: string,"created_at"?: string,"dedupe_key"?: string,"email_attempts"?: number,"email_error"?: string | null,"email_sent_at"?: string | null,"email_status"?: string,"id"?: string,"link"?: string | null,"org_id"?: string,"read_at"?: string | null,"severity"?: string,"title"?: string,"type"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "notifications_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"organizations": {
                  Row: {
                    "contact_email": string | null,"contact_phone": string | null,"created_at": string,"created_by": string | null,"data_retention_days": number,"deleted_at": string | null,"employee_range": string | null,"id": string,"industry": string | null,"is_demo": boolean,"monitoring_paused": boolean,"name": string,"onboarding_step": number,"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "contact_email"?: string | null,"contact_phone"?: string | null,"created_at"?: string,"created_by"?: string | null,"data_retention_days"?: number,"deleted_at"?: string | null,"employee_range"?: string | null,"id"?: string,"industry"?: string | null,"is_demo"?: boolean,"monitoring_paused"?: boolean,"name": string,"onboarding_step"?: number,"updated_at"?: string
                  }
                  Update: {
                    "contact_email"?: string | null,"contact_phone"?: string | null,"created_at"?: string,"created_by"?: string | null,"data_retention_days"?: number,"deleted_at"?: string | null,"employee_range"?: string | null,"id"?: string,"industry"?: string | null,"is_demo"?: boolean,"monitoring_paused"?: boolean,"name"?: string,"onboarding_step"?: number,"updated_at"?: string
                  }
                  Relationships: [
                    
                  ]
                },"plans": {
                  Row: {
                    "active": boolean,"currency": string,"description": string,"features": (string)[],"interval": string,"key": string,"limits": NonNullable<Json>,"name": string,"price_cents": number,"sort": number,"stripe_price_env": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "active"?: boolean,"currency"?: string,"description": string,"features"?: (string)[],"interval"?: string,"key": string,"limits": NonNullable<Json>,"name": string,"price_cents": number,"sort"?: number,"stripe_price_env"?: string | null
                  }
                  Update: {
                    "active"?: boolean,"currency"?: string,"description"?: string,"features"?: (string)[],"interval"?: string,"key"?: string,"limits"?: NonNullable<Json>,"name"?: string,"price_cents"?: number,"sort"?: number,"stripe_price_env"?: string | null
                  }
                  Relationships: [
                    
                  ]
                },"platform_admins": {
                  Row: {
                    "created_at": string,"user_id": string
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"user_id": string
                  }
                  Update: {
                    "created_at"?: string,"user_id"?: string
                  }
                  Relationships: [
                    
                  ]
                },"profiles": {
                  Row: {
                    "created_at": string,"full_name": string | null,"id": string,"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"full_name"?: string | null,"id": string,"updated_at"?: string
                  }
                  Update: {
                    "created_at"?: string,"full_name"?: string | null,"id"?: string,"updated_at"?: string
                  }
                  Relationships: [
                    
                  ]
                },"provider_integrations": {
                  Row: {
                    "consecutive_failures": number,"key": string,"kind": string,"label": string,"last_checked_at": string | null,"last_error_at": string | null,"last_success_at": string | null,"status": string,"status_message": string | null,"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "consecutive_failures"?: number,"key": string,"kind": string,"label": string,"last_checked_at"?: string | null,"last_error_at"?: string | null,"last_success_at"?: string | null,"status"?: string,"status_message"?: string | null,"updated_at"?: string
                  }
                  Update: {
                    "consecutive_failures"?: number,"key"?: string,"kind"?: string,"label"?: string,"last_checked_at"?: string | null,"last_error_at"?: string | null,"last_success_at"?: string | null,"status"?: string,"status_message"?: string | null,"updated_at"?: string
                  }
                  Relationships: [
                    
                  ]
                },"public_checks": {
                  Row: {
                    "created_at": string,"expires_at": string,"hostname": string,"id": string,"ip_hash": string,"job_id": string | null,"result": Json | null,"status": string
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"expires_at"?: string,"hostname": string,"id"?: string,"ip_hash": string,"job_id"?: string | null,"result"?: Json | null,"status"?: string
                  }
                  Update: {
                    "created_at"?: string,"expires_at"?: string,"hostname"?: string,"id"?: string,"ip_hash"?: string,"job_id"?: string | null,"result"?: Json | null,"status"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "public_checks_job_id_fkey"
      columns: ["job_id"]
isOneToOne: false
      referencedRelation: "scan_jobs"
      referencedColumns: ["id"]
    }
                  ]
                },"rate_limits": {
                  Row: {
                    "count": number,"key": string,"window_start": string
                  }
                  ComputedFields: never
                  Insert: {
                    "count"?: number,"key": string,"window_start": string
                  }
                  Update: {
                    "count"?: number,"key"?: string,"window_start"?: string
                  }
                  Relationships: [
                    
                  ]
                },"reports": {
                  Row: {
                    "created_at": string,"created_by": string | null,"id": string,"is_demo": boolean,"kind": string,"org_id": string,"period_end": string,"period_start": string,"snapshot": NonNullable<Json>,"storage_path": string | null
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"created_by"?: string | null,"id"?: string,"is_demo"?: boolean,"kind": string,"org_id": string,"period_end": string,"period_start": string,"snapshot": NonNullable<Json>,"storage_path"?: string | null
                  }
                  Update: {
                    "created_at"?: string,"created_by"?: string | null,"id"?: string,"is_demo"?: boolean,"kind"?: string,"org_id"?: string,"period_end"?: string,"period_start"?: string,"snapshot"?: NonNullable<Json>,"storage_path"?: string | null
                  }
                  Relationships: [
                    {
      foreignKeyName: "reports_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"roles": {
                  Row: {
                    "description": string,"key": string,"label": string,"rank": number
                  }
                  ComputedFields: never
                  Insert: {
                    "description": string,"key": string,"label": string,"rank": number
                  }
                  Update: {
                    "description"?: string,"key"?: string,"label"?: string,"rank"?: number
                  }
                  Relationships: [
                    
                  ]
                },"scan_authorizations": {
                  Row: {
                    "domain_id": string,"granted_at": string,"granted_by": string | null,"id": string,"include_subdomains": boolean,"ip_hash": string | null,"org_id": string,"revoked_at": string | null,"revoked_by": string | null,"scopes": (string)[],"signer_name": string,"signer_role": string,"statement_sha256": string,"statement_version": string,"user_agent": string | null,"valid_until": string
                  }
                  ComputedFields: never
                  Insert: {
                    "domain_id": string,"granted_at"?: string,"granted_by"?: string | null,"id"?: string,"include_subdomains"?: boolean,"ip_hash"?: string | null,"org_id": string,"revoked_at"?: string | null,"revoked_by"?: string | null,"scopes": (string)[],"signer_name": string,"signer_role": string,"statement_sha256": string,"statement_version": string,"user_agent"?: string | null,"valid_until"?: string
                  }
                  Update: {
                    "domain_id"?: string,"granted_at"?: string,"granted_by"?: string | null,"id"?: string,"include_subdomains"?: boolean,"ip_hash"?: string | null,"org_id"?: string,"revoked_at"?: string | null,"revoked_by"?: string | null,"scopes"?: (string)[],"signer_name"?: string,"signer_role"?: string,"statement_sha256"?: string,"statement_version"?: string,"user_agent"?: string | null,"valid_until"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "scan_authorizations_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "scan_authorizations_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"scan_jobs": {
                  Row: {
                    "attempts": number,"cancel_requested": boolean,"created_at": string,"domain_id": string | null,"error": string | null,"finished_at": string | null,"heartbeat_at": string | null,"id": string,"idempotency_key": string,"kind": string,"locked_at": string | null,"locked_by": string | null,"max_attempts": number,"org_id": string | null,"payload": NonNullable<Json>,"priority": number,"requested_by": string | null,"run_after": string,"started_at": string | null,"status": Database["public"]['Enums']["job_status"],"summary": Json | null,"trigger": string
                  }
                  ComputedFields: never
                  Insert: {
                    "attempts"?: number,"cancel_requested"?: boolean,"created_at"?: string,"domain_id"?: string | null,"error"?: string | null,"finished_at"?: string | null,"heartbeat_at"?: string | null,"id"?: string,"idempotency_key": string,"kind": string,"locked_at"?: string | null,"locked_by"?: string | null,"max_attempts"?: number,"org_id"?: string | null,"payload"?: NonNullable<Json>,"priority"?: number,"requested_by"?: string | null,"run_after"?: string,"started_at"?: string | null,"status"?: Database["public"]['Enums']["job_status"],"summary"?: Json | null,"trigger": string
                  }
                  Update: {
                    "attempts"?: number,"cancel_requested"?: boolean,"created_at"?: string,"domain_id"?: string | null,"error"?: string | null,"finished_at"?: string | null,"heartbeat_at"?: string | null,"id"?: string,"idempotency_key"?: string,"kind"?: string,"locked_at"?: string | null,"locked_by"?: string | null,"max_attempts"?: number,"org_id"?: string | null,"payload"?: NonNullable<Json>,"priority"?: number,"requested_by"?: string | null,"run_after"?: string,"started_at"?: string | null,"status"?: Database["public"]['Enums']["job_status"],"summary"?: Json | null,"trigger"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "scan_jobs_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "scan_jobs_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"scan_results": {
                  Row: {
                    "adapter": string,"checks": (string)[],"data": NonNullable<Json>,"domain_id": string | null,"duration_ms": number,"finished_at": string,"id": string,"job_id": string,"message": string | null,"observation_count": number,"org_id": string | null,"started_at": string,"status": string,"targets": (string)[]
                  }
                  ComputedFields: never
                  Insert: {
                    "adapter": string,"checks"?: (string)[],"data"?: NonNullable<Json>,"domain_id"?: string | null,"duration_ms": number,"finished_at": string,"id"?: string,"job_id": string,"message"?: string | null,"observation_count"?: number,"org_id"?: string | null,"started_at": string,"status": string,"targets"?: (string)[]
                  }
                  Update: {
                    "adapter"?: string,"checks"?: (string)[],"data"?: NonNullable<Json>,"domain_id"?: string | null,"duration_ms"?: number,"finished_at"?: string,"id"?: string,"job_id"?: string,"message"?: string | null,"observation_count"?: number,"org_id"?: string | null,"started_at"?: string,"status"?: string,"targets"?: (string)[]
                  }
                  Relationships: [
                    {
      foreignKeyName: "scan_results_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "scan_results_job_id_fkey"
      columns: ["job_id"]
isOneToOne: false
      referencedRelation: "scan_jobs"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "scan_results_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"service_provider_invites": {
                  Row: {
                    "access_count": number,"company_name": string | null,"contact_name": string | null,"created_at": string,"created_by": string | null,"email": string,"expires_at": string,"id": string,"last_access_at": string | null,"org_id": string,"revoked_at": string | null,"token_hash": string
                  }
                  ComputedFields: never
                  Insert: {
                    "access_count"?: number,"company_name"?: string | null,"contact_name"?: string | null,"created_at"?: string,"created_by"?: string | null,"email": string,"expires_at": string,"id"?: string,"last_access_at"?: string | null,"org_id": string,"revoked_at"?: string | null,"token_hash": string
                  }
                  Update: {
                    "access_count"?: number,"company_name"?: string | null,"contact_name"?: string | null,"created_at"?: string,"created_by"?: string | null,"email"?: string,"expires_at"?: string,"id"?: string,"last_access_at"?: string | null,"org_id"?: string,"revoked_at"?: string | null,"token_hash"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "service_provider_invites_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"service_provider_shares": {
                  Row: {
                    "created_at": string,"finding_id": string,"invite_id": string,"org_id": string
                  }
                  ComputedFields: never
                  Insert: {
                    "created_at"?: string,"finding_id": string,"invite_id": string,"org_id": string
                  }
                  Update: {
                    "created_at"?: string,"finding_id"?: string,"invite_id"?: string,"org_id"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "service_provider_shares_finding_id_fkey"
      columns: ["finding_id"]
isOneToOne: false
      referencedRelation: "findings"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "service_provider_shares_invite_id_fkey"
      columns: ["invite_id"]
isOneToOne: false
      referencedRelation: "service_provider_invites"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "service_provider_shares_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"stripe_events": {
                  Row: {
                    "id": string,"received_at": string,"type": string
                  }
                  ComputedFields: never
                  Insert: {
                    "id": string,"received_at"?: string,"type": string
                  }
                  Update: {
                    "id"?: string,"received_at"?: string,"type"?: string
                  }
                  Relationships: [
                    
                  ]
                },"subscriptions": {
                  Row: {
                    "cancel_at_period_end": boolean,"created_at": string,"current_period_end": string | null,"id": string,"org_id": string,"plan_key": string,"status": string,"stripe_customer_id": string | null,"stripe_subscription_id": string | null,"trial_ends_at": string | null,"updated_at": string
                  }
                  ComputedFields: never
                  Insert: {
                    "cancel_at_period_end"?: boolean,"created_at"?: string,"current_period_end"?: string | null,"id"?: string,"org_id": string,"plan_key": string,"status": string,"stripe_customer_id"?: string | null,"stripe_subscription_id"?: string | null,"trial_ends_at"?: string | null,"updated_at"?: string
                  }
                  Update: {
                    "cancel_at_period_end"?: boolean,"created_at"?: string,"current_period_end"?: string | null,"id"?: string,"org_id"?: string,"plan_key"?: string,"status"?: string,"stripe_customer_id"?: string | null,"stripe_subscription_id"?: string | null,"trial_ends_at"?: string | null,"updated_at"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "subscriptions_org_id_fkey"
      columns: ["org_id"]
isOneToOne: true
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "subscriptions_plan_key_fkey"
      columns: ["plan_key"]
isOneToOne: false
      referencedRelation: "plans"
      referencedColumns: ["key"]
    }
                  ]
                },"timeline_events": {
                  Row: {
                    "body": string | null,"created_at": string,"data": NonNullable<Json>,"domain_id": string | null,"finding_id": string | null,"id": string,"is_demo": boolean,"link": string | null,"org_id": string,"severity": string,"title": string,"type": string
                  }
                  ComputedFields: never
                  Insert: {
                    "body"?: string | null,"created_at"?: string,"data"?: NonNullable<Json>,"domain_id"?: string | null,"finding_id"?: string | null,"id"?: string,"is_demo"?: boolean,"link"?: string | null,"org_id": string,"severity"?: string,"title": string,"type": string
                  }
                  Update: {
                    "body"?: string | null,"created_at"?: string,"data"?: NonNullable<Json>,"domain_id"?: string | null,"finding_id"?: string | null,"id"?: string,"is_demo"?: boolean,"link"?: string | null,"org_id"?: string,"severity"?: string,"title"?: string,"type"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "timeline_events_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "timeline_events_finding_id_fkey"
      columns: ["finding_id"]
isOneToOne: false
      referencedRelation: "findings"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "timeline_events_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                },"verification_challenges": {
                  Row: {
                    "attempts": number,"consumed_at": string | null,"created_at": string,"domain_id": string,"expires_at": string,"id": string,"last_checked_at": string | null,"last_result": string | null,"org_id": string,"record_name": string,"token": string
                  }
                  ComputedFields: never
                  Insert: {
                    "attempts"?: number,"consumed_at"?: string | null,"created_at"?: string,"domain_id": string,"expires_at"?: string,"id"?: string,"last_checked_at"?: string | null,"last_result"?: string | null,"org_id": string,"record_name": string,"token": string
                  }
                  Update: {
                    "attempts"?: number,"consumed_at"?: string | null,"created_at"?: string,"domain_id"?: string,"expires_at"?: string,"id"?: string,"last_checked_at"?: string | null,"last_result"?: string | null,"org_id"?: string,"record_name"?: string,"token"?: string
                  }
                  Relationships: [
                    {
      foreignKeyName: "verification_challenges_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "verification_challenges_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                }
          }
          Views: {
            "domain_coverage": {
                  Row: {
                    "adapter": string,"checks": (string)[],"domain_id": string | null,"finished_at": string,"message": string | null,"org_id": string | null,"status": string,"targets": (string)[]
                  }
                  ComputedFields: never
                  Relationships: [
                    {
      foreignKeyName: "scan_results_domain_id_fkey"
      columns: ["domain_id"]
isOneToOne: false
      referencedRelation: "domains"
      referencedColumns: ["id"]
    },{
      foreignKeyName: "scan_results_org_id_fkey"
      columns: ["org_id"]
isOneToOne: false
      referencedRelation: "organizations"
      referencedColumns: ["id"]
    }
                  ]
                }
          }
          Functions: {
            "claim_scan_job":
{ Args: { "p_kinds": (string)[],"p_worker": string }; Returns: {
              "attempts": number,
"cancel_requested": boolean,
"created_at": string,
"domain_id": string | null,
"error": string | null,
"finished_at": string | null,
"heartbeat_at": string | null,
"id": string,
"idempotency_key": string,
"kind": string,
"locked_at": string | null,
"locked_by": string | null,
"max_attempts": number,
"org_id": string | null,
"payload": NonNullable<Json>,
"priority": number,
"requested_by": string | null,
"run_after": string,
"started_at": string | null,
"status": Database["public"]['Enums']["job_status"],
"summary": Json | null,
"trigger": string
            }[]
                          SetofOptions: {
        from: "*"
        to: "scan_jobs"
        isOneToOne: false
        isSetofReturn: true
      } },
"create_organization":
{ Args: { "p_contact_email": string,"p_employee_range": string,"p_industry": string,"p_name": string,"p_user": string }; Returns: string
                           },
"is_org_member":
{ Args: { "p_org": string }; Returns: boolean
                           },
"is_platform_admin":
{ Args: Record<PropertyKey, never>; Returns: boolean
                           },
"org_role_rank":
{ Args: { "p_org": string }; Returns: number
                           },
"rate_limit_hit":
{ Args: { "p_key": string,"p_max": number,"p_window_seconds": number }; Returns: boolean
                           },
"requeue_stale_jobs":
{ Args: { "p_stale_seconds"?: number }; Returns: number
                           }
          }
          Enums: {
            "confidence_level": "high"|"medium"|"low","domain_verification_status": "pending"|"verified"|"failed"|"expired","finding_certainty": "confirmed"|"potential"|"informational"|"not_checkable","finding_severity": "critical"|"high"|"medium"|"low"|"info","finding_status": "new"|"investigating"|"action_required"|"resolved"|"accepted_risk"|"false_positive","job_status": "queued"|"running"|"succeeded"|"failed"|"cancelled"
          }
          CompositeTypes: {
            [_ in never]: never
          }
        }
}

type DatabaseWithoutInternals = Omit<Database, '__InternalSupabase'>

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
  ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
      Row: infer R
    }
    ? R
    : never
  : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
  ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
      Insert: infer I
    }
    ? I
    : never
  : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
  ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
      Update: infer U
    }
    ? U
    : never
  : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never
> = DefaultSchemaEnumNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
  ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
  : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never
> = PublicCompositeTypeNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
  ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
  : never

export const Constants = {
  "graphql_public": {
          Enums: {
            
          }
        },"public": {
          Enums: {
            "confidence_level": ["high", "medium", "low"],"domain_verification_status": ["pending", "verified", "failed", "expired"],"finding_certainty": ["confirmed", "potential", "informational", "not_checkable"],"finding_severity": ["critical", "high", "medium", "low", "info"],"finding_status": ["new", "investigating", "action_required", "resolved", "accepted_risk", "false_positive"],"job_status": ["queued", "running", "succeeded", "failed", "cancelled"]
          }
        }
} as const

import os

models_dir = r"d:\BlockBord_Premium_SaaS_Style\Block Bord\app\Models"

models = [
    ("UserProfile", "user_profiles", ""),
    ("Role", "roles", ""),
    ("SubscriptionPlan", "subscription_plans", ""),
    ("ScanResult", "scan_results", "    protected $casts = ['findings' => 'array'];"),
    ("ScanFeature", "scan_features", "    protected $casts = ['features_json' => 'array'];"),
    ("ScanReport", "scan_reports", ""),
    ("AiMessage", "ai_messages", ""),
    ("BlockedIp", "blocked_ips", ""),
    ("EmailBreach", "email_breaches", "    protected $casts = ['breach_date' => 'date'];"),
    ("PhoneReport", "phone_reports", ""),
    ("FileScan", "file_scans", ""),
    ("FileHash", "file_hashes", ""),
    ("SecurityScore", "security_scores", "    protected $casts = ['factors' => 'array'];"),
    ("SecurityAlert", "security_alerts", "    protected $casts = ['is_read' => 'boolean'];"),
    ("ApiUsage", "api_usage", "    protected $casts = ['date' => 'date'];\n    protected $table = 'api_usage';"),
    ("ToolUsage", "tool_usage", "    protected $table = 'tool_usage';"),
    ("AuditLog", "audit_logs", "")
]

template = """<?php

namespace App\\Models;

use Illuminate\\Database\\Eloquent\\Factories\\HasFactory;
use Illuminate\\Database\\Eloquent\\Model;

class {model_name} extends Model
{{
    use HasFactory;

    protected $guarded = [];

{extra}
}}
"""

for model_name, table_name, extra in models:
    filepath = os.path.join(models_dir, f"{model_name}.php")
    content = template.format(model_name=model_name, extra=extra)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

print(f"Created {len(models)} models successfully.")

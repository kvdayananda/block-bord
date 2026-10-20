import os
import datetime

migrations_dir = r"d:\BlockBord_Premium_SaaS_Style\Block Bord\database\migrations"
date_prefix = "2026_01_01_0000"

tables = [
    ("15", "create_user_profiles_table", "user_profiles", "            $table->id();\n            $table->foreignId('user_id')->constrained()->cascadeOnDelete();\n            $table->string('first_name')->nullable();\n            $table->string('last_name')->nullable();\n            $table->string('company')->nullable();\n            $table->string('avatar_url')->nullable();\n            $table->timestamps();"),
    ("16", "create_roles_table", "roles", "            $table->id();\n            $table->string('name')->unique();\n            $table->string('description')->nullable();\n            $table->timestamps();"),
    ("17", "create_subscription_plans_table", "subscription_plans", "            $table->id();\n            $table->string('plan_name');\n            $table->decimal('price', 8, 2);\n            $table->json('limits')->nullable();\n            $table->timestamps();"),
    ("18", "create_scan_results_table", "scan_results", "            $table->id();\n            $table->foreignId('scan_id')->constrained('scans')->cascadeOnDelete();\n            $table->string('scanner_name');\n            $table->json('findings')->nullable();\n            $table->timestamps();"),
    ("19", "create_scan_features_table", "scan_features", "            $table->id();\n            $table->foreignId('scan_id')->constrained('scans')->cascadeOnDelete();\n            $table->json('features_json')->nullable();\n            $table->timestamps();"),
    ("20", "create_scan_reports_table", "scan_reports", "            $table->id();\n            $table->foreignId('scan_id')->constrained('scans')->cascadeOnDelete();\n            $table->string('pdf_url')->nullable();\n            $table->timestamps();"),
    ("21", "create_ai_messages_table", "ai_messages", "            $table->id();\n            $table->foreignId('conversation_id')->constrained('ai_conversations')->cascadeOnDelete();\n            $table->string('role');\n            $table->text('content');\n            $table->timestamps();"),
    ("22", "create_blocked_ips_table", "blocked_ips", "            $table->id();\n            $table->string('ip_address')->unique();\n            $table->string('reason')->nullable();\n            $table->timestamps();"),
    ("23", "create_email_breaches_table", "email_breaches", "            $table->id();\n            $table->string('email')->index();\n            $table->string('breach_name');\n            $table->date('breach_date')->nullable();\n            $table->timestamps();"),
    ("24", "create_phone_reports_table", "phone_reports", "            $table->id();\n            $table->string('phone_number')->index();\n            $table->integer('spam_score')->default(0);\n            $table->timestamps();"),
    ("25", "create_file_scans_table", "file_scans", "            $table->id();\n            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();\n            $table->string('file_hash')->index();\n            $table->string('file_name');\n            $table->integer('risk_score')->default(0);\n            $table->timestamps();"),
    ("26", "create_file_hashes_table", "file_hashes", "            $table->id();\n            $table->string('hash')->unique();\n            $table->string('status');\n            $table->timestamps();"),
    ("27", "create_security_scores_table", "security_scores", "            $table->id();\n            $table->foreignId('user_id')->constrained()->cascadeOnDelete();\n            $table->integer('score')->default(100);\n            $table->json('factors')->nullable();\n            $table->timestamps();"),
    ("28", "create_security_alerts_table", "security_alerts", "            $table->id();\n            $table->foreignId('user_id')->constrained()->cascadeOnDelete();\n            $table->string('alert_type');\n            $table->text('message');\n            $table->boolean('is_read')->default(false);\n            $table->timestamps();"),
    ("29", "create_api_usage_table", "api_usage", "            $table->id();\n            $table->foreignId('user_id')->constrained()->cascadeOnDelete();\n            $table->string('endpoint');\n            $table->integer('requests')->default(1);\n            $table->date('date');\n            $table->timestamps();"),
    ("30", "create_tool_usage_table", "tool_usage", "            $table->id();\n            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();\n            $table->string('tool_name');\n            $table->timestamps();"),
    ("31", "create_audit_logs_table", "audit_logs", "            $table->id();\n            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();\n            $table->string('action');\n            $table->text('details')->nullable();\n            $table->string('ip_address')->nullable();\n            $table->timestamps();"),
    ("32", "create_sessions_table", "sessions", "            $table->string('id')->primary();\n            $table->foreignId('user_id')->nullable()->index();\n            $table->string('ip_address', 45)->nullable();\n            $table->text('user_agent')->nullable();\n            $table->longText('payload');\n            $table->integer('last_activity')->index();")
]

template = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration
{{
    public function up(): void
    {{
        Schema::create('{table_name}', function (Blueprint $table) {{
{columns}
        }});
    }}

    public function down(): void
    {{
        Schema::dropIfExists('{table_name}');
    }}
}};
"""

for num, name, table_name, columns in tables:
    filename = f"{date_prefix}{num}_{name}.php"
    filepath = os.path.join(migrations_dir, filename)
    content = template.format(table_name=table_name, columns=columns)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

print(f"Created {len(tables)} migrations successfully.")
